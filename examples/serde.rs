use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ziffle::{
    AggregatePublicKey, MaskedDeck, OwnershipProof, PublicKey, RevealToken, RevealTokenProof,
    SecretKey, ShuffleProof,
};

const DECK_SIZE: usize = 52;
type Shuffle = ziffle::Shuffle<DECK_SIZE>;

fn main() {
    let mut rng = rand::thread_rng();

    let shuffle = Shuffle::default();

    let ctx = b"serde";

    let (sk, pk, id_proof) = shuffle.keygen(&mut rng, ctx);
    let vpk = id_proof.verify(pk, ctx).unwrap();

    let apk = AggregatePublicKey::new(&[vpk]);

    let (deck, shfl_proof) = shuffle.shuffle_initial_deck(&mut rng, apk, ctx);
    let vdeck = shuffle
        .verify_initial_shuffle(apk, deck, shfl_proof, ctx)
        .unwrap();

    let card = vdeck.get(0).unwrap();

    let (reveal_token, reveal_proof) = card.reveal_token(&mut rng, &sk, pk, ctx);

    let mut sk_bytes = vec![];
    sk.serialize_compressed(&mut sk_bytes).unwrap();
    let _ = SecretKey::deserialize_compressed(&sk_bytes[..]).unwrap();

    let mut pk_bytes = vec![];
    pk.serialize_compressed(&mut pk_bytes).unwrap();
    let _ = PublicKey::deserialize_compressed(&pk_bytes[..]).unwrap();

    let mut id_proof_bytes = vec![];
    id_proof.serialize_compressed(&mut id_proof_bytes).unwrap();
    let _ = OwnershipProof::deserialize_compressed(&id_proof_bytes[..]).unwrap();

    let mut deck_bytes = vec![];
    deck.serialize_compressed(&mut deck_bytes).unwrap();
    let _ = MaskedDeck::<DECK_SIZE>::deserialize_compressed(&deck_bytes[..]).unwrap();

    let mut shfl_proof_bytes = vec![];
    shfl_proof
        .serialize_compressed(&mut shfl_proof_bytes)
        .unwrap();
    let _ = ShuffleProof::<DECK_SIZE>::deserialize_compressed(&shfl_proof_bytes[..]).unwrap();

    let mut reveal_token_bytes = vec![];
    reveal_token
        .serialize_compressed(&mut reveal_token_bytes)
        .unwrap();
    let _ = RevealToken::deserialize_compressed(&reveal_token_bytes[..]).unwrap();

    let mut reveal_proof_bytes = vec![];
    reveal_proof
        .serialize_compressed(&mut reveal_proof_bytes)
        .unwrap();
    let _ = RevealTokenProof::deserialize_compressed(&reveal_proof_bytes[..]).unwrap();

    println!("public key: {} bytes", pk_bytes.len());
    println!("secret key: {} bytes", sk_bytes.len());
    println!("ownership proof: {} bytes", id_proof_bytes.len());
    println!("{DECK_SIZE} card deck: {} bytes", deck_bytes.len());
    println!(
        "{DECK_SIZE} shuffle proof: {} bytes",
        shfl_proof_bytes.len()
    );
    println!("reveal token: {} bytes", reveal_token_bytes.len());
    println!("reveal token proof: {} bytes", reveal_proof_bytes.len());
}
