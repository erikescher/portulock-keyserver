# PortuLock Keyserver

PortuLock is a  privacy preserving keyserver and certificate authority for organizations 
that solves the problems associated with privacy considerations around key distribution 
as well as the verification of keys for internal and external communication partners.

It allows users to generate keys, have them certified and published as well as manage their
lifecycle on their own by authenticating with the organization’s existing single-sign-on
infrastructure to verify their name and prove membership in the organization.
Keys remain in the sole control of the user, while PortuLock’s web generator takes care
of complex processes such as creating trust signatures over certificate authority keys,
that are not exposed by all clients.

On the privacy front it gives users full control over what information can be distributed
with their certificate to protect against denial of service, distribution of problematic
materials and to prevent leaking the social graph of certifications. It also ensures that
data can only be published with approval from the subjects to which it pertains.
When it comes to identity validation, PortuLock leverages the network of trusted certificates 
spanned by the OpenPGP-CA project and library while making it accessible and
usable for organizations of all sized due to the scalable and easy self-service approach to
certification.

It extends this network by providing an aggregation feature that requests keys for email
addresses directly from the target domain using established protocols and without leaking
personally identifiable information such as email addresses and fingerprints to third-parties
as is common with centralized keyservers. This aggregation feature allows administrators
to configure trust based on the origin of a key and in turn issue certifications
on the fly, extending this trust to clients and lifting the burden of verification from the
users.

In summary, PortuLock makes OpenPGP usable for organizations by providing a scalable trust
system, that users can easily join while also protecting their privacy and the privacy of 
communication partners by requesting information about certificates directly from the 
respective domains.

## Configuration
This project uses the [Rocket framework](https://rocket.rs/v0.4/) for its web server components and
can be configured through its configuration system. This means creating configuration
files in Tom’s Obvious, Minimal Language (TOML) format for each of the services or
providing configuration using environment variables. The configuration files are called
aggregator.toml and verifier.toml respectively and are mapped into the containers
as read-only files.

Details on configuration options can be found in the 
[Rocket documentation](https://rocket.rs/v0.4/guide/configuration/#configuration).

### Verifier
The configuration consists of the domains, that the keyserver is responsible for and will
accept in UserIDs in the key `allowed_domains`, a list of ASCII armored public keys,
whose certifications on any key are redistributed even without attestation in the key
`allowed_certifying_keys` as well as configuration for OIDC (`oidc_*`) and Simple Mail
Transfer Protocol (SMTP) (`smtp_*`).

Additionally, two secret keys need to be provided in `secret_key` and `token_signing_key`, 
that are used to encrypt a cookie keeping temporary state for the OIDC process and
sign tokens used for verification. The latter can be used to generate such tokens if needed
in automation scripts.

Ports, listening addresses and paths are provided in the docker environment but need to be configured otherwise.

Example:
```toml
[global]
secret_key = "Ie<REDACTED>Bo=" # 256bit, base64
token_signing_key = "ZGVtbw==" # base64("demo")

external_url = "https://keyserver.example.org"

allowed_domain = "example.org"
allowed_certifying_keys = [
  "<ASCII Armored Public Key for a CA>",
  "<...>"
]

smtp_host = "smtp.example.org"
smtp_port = 465
smtp_user = "openpgp-ca"
smtp_pass = "<REDACTED>"
smtp_from = "openpgp-ca@example.org"

oidc_issuer_url = "https://sso.example.org"
oidc_client_id = "<REDACTED>"
oidc_client_secret = "<REDACTED>"
```

### Aggregator
The configuration for the Aggregator service consists of a map containing special con-
figuration for domains with known keyservers and CAs followed by a set of fallbacks
that will be applied if no domain specific configuration can be found.

For each entry (both in the special domains and fallbacks) a set of keyservers can be
defined and the administrator can choose whether to use WKD. The server will retrieve
key information from all of these sources simultaneously before filtering any UserIDs
it encounters by the requested domain. Afterwards, if a set of CAs is configured, only
UserIDs certified by one of the CAs will be retained. Any remaining UserIDs will be
certified as configured before returning any keys to the client, that still have at 
least one UserID on them.

This provides a flexible system that can be adapted to the organization’s needs regarding
security, privacy and usability.

The example below shows the Aggregator configuration used by `example.org`.
Keys belonging to the organization can be queried from the WKD and are known to be
signed by the organization’s CA.

Keys for `alice.tld`, a partner organization that also uses this project’s keyserver (or a
different solution using OpenPGP-CA), are queried directly from their domain’s WKD
keystore as well and similarly expected to be signed by their CA. Since their CA has been
trust signed by the example.org CA, all of its members already trust the certifications
and no on-the-fly certification is required.

Keys for `bob.tld` are not available via WKD but offered on the organizations keyserver
using a secure connection. Unfortunately, these keys are not certified so the Aggregator
service will sign UserIDs retrieved from this server that match the correct domain automatically
as they pass through the service. The private key configured here has been trust signed by the CA
for the respective domain.

For requests that don’t match one of the above domains, both the WKD and the specified
public keyservers are queried. Keys retrieved via WKD are certified as they pass through
the service, while others are passed through without further trust being applied.

```toml
[global.lookup_config.special_domains."example.org"]
use_wkd = true
expect_one_certification_from = [
  "<Armored Public Key for openpgp-ca@example.org>"
]

[global.lookup_config.special_domains."alice.tld"]
use_wkd = true
expect_one_certification_from = [
  "<Armored Public Key for openpgp-ca@alice.tld>"
]

[global.lookup_config.special_domains."bob.tld"]
keyservers = ["hkps://keys.bob.tld"]
certifier = "<Armored Private Key used for Certification>"

[global.lookup_config.fallbacks.wkd_fallback]
use_wkd = true
certifier = "<Armored Private Key used for Certification>"

[global.lookup_config.fallbacks.keyserver_fallback]
keyservers = ["hkps://keys.openpgp.org"]
```

### Generating the CA Certificate
When the verifier starts for the first time for a specific domain, it generates a CA
certificate automatically. The CA certificate will use the UserID `OpenPGP-CA <openpgp -ca@<domain>`,
to customize this, in particular to change the name from “OpenPGP-CA”
to the name of the organization. The OpenPGP-CA CLI can be used to generate the
certificate before starting the service.

This certificate will be used to sign all other certificates and will be published along
with them. It can be exported using the OpenPGP-CA CLI and should be backed up
securely.

### Web Generator
Each time the web generator gets loaded in a user’s browser, it fetches its configuration
from the path `/config/ui.json` on the same domain that it was loaded from.
The `key_generation` object gets passed directly to the “openpgp.js” library during key
generation and can be used to configure the key composition as desired. Subkeys, key
usage flags and expiration times among other things can be defined using this key. Refer to
[their documentation](https://openpgpjs.org/openpgpjs/global.html#generateKey) for details.

The `trust_sign` array should contain a list of certificate authorities managed by this
server. The generator will trust-sign these during key generation and provide the signed
certificates to the user for download and importation into their client. They will also be
provided in unsigned form on a “CA List” page.

Any requests will be performed against the PortuLock keyserver operating on the same
domain, the web generator was loaded from.
The example provided below shows an appropriate configuration for the `example.org` organization.
The web generator can be served from multiple domains with independent configuration
files if different configuration for multiple domains operated by the same keyserver is
desired. Directing their users to the correct web generator instance is then up to the
organization.

```json
{
  "key_generation": {
    "type": "rsa",
    "rsaBits": 4096,
    "keyExpirationTime": 94608000
  },
  "trust_sign": [
    {
      "ca": "<Armored Public Key for the CA>",
      "domain_scope": "example.org",
      "name": "Example.org CA"
    }
  ]
}
```

## Distribution

### Packages
This project is distributed as source code and no packages, containers or binaries are currently provided.
Compilation into docker containers is recommended to simplify dependency management and create a reproducible 
environment on the server.

Having users compile the source code provides them assurance that the resulting binaries actually match the 
source code and reduces the potential for undetected supply chain attacks.

Rust crates and containers might be provided on crates.io and Docker Hub later to simplify use without Docker,
however containers make verifying that the source matches the final container difficult.

For development individual components can be compiled without docker using cargo
build or compiled and executed using cargo run, reducing compile times and allowing for debugging.

### License
This project is released under the GPL license as required by the openpgp-ca-lib library and the
static linking of the sequoia library, which is available under the LGPL license.

## Deployment
This project uses Docker and Docker Compose to simplify dependency management and
provide a consistent and isolated runtime environment.

### Obtaining the Code
The source code for PortuLock can be obtained from GitHub using `git clone https://gitlab.com/portulock/portulock-keyserver.git`.
All commits and tags in this repository are signed by the author to ensure code integrity.

### Compiling
This project uses Docker and Docker Compose to simplify installation and dependency management. 

The services can be built from source by running `docker -compose build`. 

This fetches the dependencies needed to compile and run the project, compiles the rust binaries 
from source and builds docker containers, that will be executed later.

### Starting the Services
The services can be started by running docker-compose up -d. This will compare the
currently running services with the ones defined in the docker-compose file, creating,
starting and stopping them as needed to achieve the defined configuration.

### Scaling Horizontally
Docker Compose allows the administrator to start multiple instances of the same ser-
vice using the `--scale` parameter when starting such as `-–scale aggregator=5 -–scale
nginx=10`. 

Load will be balanced between these instances using the round-robin system of the docker internal DNS service.
Additional tools such as Docker Swarm or Kubernetes could be used to deploy the containers if required.

This can also be used to omit unused services by scaling them to zero.

### Updating Code and Dependencies
Updates to the source code can be retrieved using `git pull`, after which the release
notes and change log should be checked for any changes that need to be made to the
configuration or migrations that need to be applied manually.

Afterwards, the images can be recompiled and the service restarted in its new version
as described above.

As this project uses Docker images, effectively installing entire operating systems (with-
out their kernel), images should be regularly rebuilt even if the project itself did not
change.

Unused images, especially the ones used for compilation can occupy a lot of space. They
can be cleaned up using `docker system prune --all`.

### Persistent Data
Only the configuration for the services and the OpenPGP-CA database needs to be
persisted and backed up. The rest of the data is only temporary and can be recreated as
needed. The WKD directory is derived from the OpenPGP-CA database and the verifier
database only stores pending verifications that can simply be restarted as needed.

### Without Docker
Should Docker not be desired, all of these steps can be performed without it by using
the `docker-compose.yml` and `Dockerfile` files as a reference for what needs to be done.

### Reverse Proxy for TLS Termination
PortuLock expects to be run behind a reverse proxy that provides TLS termination to
simplify the setup and allow PortuLock to coexist with other services on the same IP
address and port. Encrypted connections are required to ensure integrity, authenticity
and confidentiality for clients performing lookups or submitting keys and especially pre-
venting interception of SSO token information. Furthermore, WKD requires certificates
to be served over TLS to ensure that they are indeed published by the domain and
prevent attacks.

The same reverse proxy can also be used to log requests for audit purposes as required.
For example one might want to log requests to the certificate update and verification
endpoints including their payload but might not want (or be allowed) to log lookup re-
quests. Separating these logs from the application ensures their availability and integrity
even if the keyserver itself might be compromised.

This reverse proxy must receive and forward traffic for the domain `openpgpkey.<domain>`,
that will be used by WKD clients to locate keys and an additional domain such as
`keyserver.<domain>` that clients will use to contact the server for API interactions and
the web generator.

## Further Details
Further details are described in the associated master thesis, that will likely be published here later.

----
Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.