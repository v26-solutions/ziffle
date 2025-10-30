use rand::RngCore;
use ziffle::{
    AggregatePublicKey, AggregateRevealToken, MaskedCard, PublicKey, SecretKey, Verified,
};

type Shuffle = ziffle::Shuffle<52>;

fn reveal_card(
    rng: &mut impl RngCore,
    s: Shuffle,
    keys: &[(SecretKey, PublicKey, Verified<PublicKey>)],
    card: MaskedCard,
    ctx: &[u8],
) -> (&'static str, &'static str) {
    let vrts: Vec<_> = keys
        .iter()
        .map(|(sk, pk, vpk)| {
            let (rt, proof) = card.reveal_token(rng, sk.clone(), *pk, ctx);
            proof.verify(*vpk, rt, card, ctx).unwrap()
        })
        .collect();

    let art = AggregateRevealToken::new(&vrts);

    let idx = s.reveal_card(art, card).unwrap();

    let suit = match idx / 13 {
        0 => "♣",
        1 => "♦",
        2 => "♥",
        3 => "♠",
        _ => unreachable!(),
    };

    let card = match idx % 13 {
        0 => "2",
        1 => "3",
        2 => "4",
        3 => "5",
        4 => "6",
        5 => "7",
        6 => "8",
        7 => "9",
        8 => "10",
        9 => "J",
        10 => "Q",
        11 => "K",
        12 => "A",
        _ => unreachable!(),
    };

    (suit, card)
}

fn main() {
    let mut rng = rand::thread_rng();

    let shuffle = Shuffle::default();

    let ctx = b"holdem";

    let (hal_sk, hal_pk, hal_id_proof) = shuffle.keygen(&mut rng, ctx);
    let (bob_sk, bob_pk, bob_id_proof) = shuffle.keygen(&mut rng, ctx);
    let (jim_sk, jim_pk, jim_id_proof) = shuffle.keygen(&mut rng, ctx);

    let hal_vpk = hal_id_proof.verify(hal_pk, ctx).unwrap();
    let bob_vpk = bob_id_proof.verify(bob_pk, ctx).unwrap();
    let jim_vpk = jim_id_proof.verify(jim_pk, ctx).unwrap();

    let apk = AggregatePublicKey::new(&[hal_vpk, bob_vpk, jim_vpk]);

    let (hal_deck, hal_shfl_proof) = shuffle.shuffle_initial_deck(&mut rng, apk, ctx);
    let hal_vdeck = shuffle
        .verify_initial_shuffle(apk, hal_deck, hal_shfl_proof, ctx)
        .unwrap();

    let (bob_deck, bob_shfl_proof) = shuffle.shuffle_deck(&mut rng, apk, &hal_vdeck, ctx);
    let bob_vdeck = shuffle
        .verify_shuffle(apk, &hal_vdeck, bob_deck, bob_shfl_proof, ctx)
        .unwrap();

    let (jim_deck, jim_shfl_proof) = shuffle.shuffle_deck(&mut rng, apk, &bob_vdeck, ctx);

    let final_vdeck = shuffle
        .verify_shuffle(apk, &bob_vdeck, jim_deck, jim_shfl_proof, ctx)
        .unwrap();

    let keys = &[
        (hal_sk, hal_pk, hal_vpk),
        (bob_sk, bob_pk, bob_vpk),
        (jim_sk, jim_pk, jim_vpk),
    ];

    let mut reveal = |i, ctx: &str| {
        reveal_card(
            &mut rng,
            shuffle,
            keys,
            final_vdeck.get(i).unwrap(),
            ctx.as_bytes(),
        )
    };

    let (hal_hole_s1, hal_hole_c1) = reveal(0, "hal_hole1");
    let (hal_hole_s2, hal_hole_c2) = reveal(1, "hal_hole2");
    println!("Hal: {hal_hole_c1}{hal_hole_s1} {hal_hole_c2}{hal_hole_s2}");

    let (bob_hole_s1, bob_hole_c1) = reveal(2, "bob_hole1");
    let (bob_hole_s2, bob_hole_c2) = reveal(3, "bob_hole2");
    println!("Bob: {bob_hole_c1}{bob_hole_s1} {bob_hole_c2}{bob_hole_s2}");

    let (jim_hole_s1, jim_hole_c1) = reveal(4, "jim_hole1");
    let (jim_hole_s2, jim_hole_c2) = reveal(5, "jim_hole2");
    println!("Jim: {jim_hole_c1}{jim_hole_s1} {jim_hole_c2}{jim_hole_s2}");

    let (flop_s1, flop_c1) = reveal(7, "flop1");
    let (flop_s2, flop_c2) = reveal(8, "flop2");
    let (flop_s3, flop_c3) = reveal(9, "flop3");

    let (turn_s, turn_c) = reveal(10, "turn");

    let (river_s, river_c) = reveal(11, "river");
    println!(
        "CC: {flop_c1}{flop_s1} {flop_c2}{flop_s2} {flop_c3}{flop_s3} {turn_c}{turn_s} {river_c}{river_s}"
    );
}
