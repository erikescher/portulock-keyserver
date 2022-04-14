use rand::Rng;

pub fn random_key() -> Vec<u8> {
    rand::thread_rng().gen::<[u8; 32]>().to_vec()
}
