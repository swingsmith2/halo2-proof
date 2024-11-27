use halo2_proofs::poly::commitment::Params;
use halo2_proofs::pasta::EqAffine;
use std::sync::LazyLock;
use rand::Rng;

// 使用 LazyLock 来确保每个字段只初始化一次
static A: LazyLock<u64> = LazyLock::new(|| {
    generate_random_u64_between_10_and_20_digits()
});

static B: LazyLock<u64> = LazyLock::new(|| {
    generate_random_u64_between_10_and_20_digits()
});

static C: LazyLock<u64> = LazyLock::new(|| {
    generate_random_u64_between_10_and_20_digits()
});

static D: LazyLock<u64> = LazyLock::new(|| {
    generate_random_u64_between_10_and_20_digits()
});

static PARAMS: LazyLock<Params<EqAffine>> = LazyLock::new(|| {
    Params::new(5)
});

pub struct Config {
    pub a: &'static u64,
    pub b: &'static u64,
    pub c: &'static u64,
    pub d: &'static u64,
    pub params: &'static Params<EqAffine>,
}

pub fn get_config() -> Config {
    Config {
        a: &*A,
        b: &*B,
        c: &*C,
        d: &*D,
        params: &*PARAMS,
    }
}

pub fn generate_random_u64_between_10_and_20_digits() -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1_000_000_000..=18_446_744_073_709)
}