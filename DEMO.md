# Public DEMO Environment

There is a demo environment available at https://demo.portulock.org which usually runs code from the master branch at https://gitlab.com/portulock/portulock-keyserver.
Sometimes newer code might run instead.

It accepts keys for the domain `demo.portulock.org` and ignores any UserIDs that don't contain email addresses using this domain.

Confirmation emails sent from the demo environment are available at https://mailcatcher.demo.portulock.org.

Name verification is handled using an Auth0 Tenant with the following users:

| Email               | Password   | Full Name |
|---------------------|------------|-----------|
| alice@portulock.org | Battleaxe1 | Alice     |
| bob@portulock.org   | Battleaxe1 | Bob       |
| john@portulock.org  | Battleaxe1 | John Doe  |

# Local DEMO Environment
To be added later based on docker-compose.
