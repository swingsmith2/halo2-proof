use group::ff::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{ 
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error, Fixed, Instance, Selector, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use std::marker::PhantomData;
use halo2_proofs::pasta::EqAffine;
use std::io;

use crate::config::{generate_random_u64_between_10_and_20_digits, get_config};

//f(x)=ax^3 + bx^2 + cx + d 在某个点 x0 上的值为 y0
// 定义多项式指令
trait PolynomialInstructions<F: Field>: Chip<F> {
    type Num;

    fn load_private(&self, layouter: impl Layouter<F>, a: Value<F>) -> Result<Self::Num, Error>;
    fn load_constant(&self, layouter: impl Layouter<F>, constant: F) -> Result<Self::Num, Error>;
    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;
    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error>;
}

// 实现多项式芯片
struct PolynomialChip<F: Field> {
    config: PolynomialConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
struct PolynomialConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    s_mul: Selector,
    s_add: Selector,
}

impl<F: Field> PolynomialChip<F> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_equality(instance);
        meta.enable_constant(constant);
        for column in &advice {
            meta.enable_equality(*column);
        }
        let s_mul = meta.selector();
        let s_add = meta.selector();

        // 定义乘法门
        meta.create_gate("mul", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let s_mul = meta.query_selector(s_mul);
            vec![s_mul * (lhs * rhs - out)]
        });

        // 定义加法门
        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let s_add = meta.query_selector(s_add);
            vec![s_add * (lhs + rhs - out)]
        });

        PolynomialConfig {
            advice,
            instance,
            s_mul,
            s_add,
        }
    }
}

impl<F: Field> Chip<F> for PolynomialChip<F> {
    type Config = PolynomialConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Clone)]
struct Number<F: Field>(AssignedCell<F, F>);

impl<F: Field> PolynomialInstructions<F> for PolynomialChip<F> {
    type Num = Number<F>;

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| {
                region
                    .assign_advice(|| "private input", config.advice[0], 0, || value)
                    .map(Number)
            },
        )
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load constant",
            |mut region| {
                region
                    .assign_advice_from_constant(|| "constant value", config.advice[0], 0, constant)
                    .map(Number)
            },
        )
    }

    fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                config.s_mul.enable(&mut region, 0)?;
                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;
                let value = a.0.value().copied() * b.0.value();
                region
                    .assign_advice(|| "lhs * rhs", config.advice[2], 0, || value)
                    .map(Number)
            },
        )
    }

    fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add",
            |mut region: Region<'_, F>| {
                config.s_add.enable(&mut region, 0)?;
                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;
                let value = a.0.value().copied() + b.0.value();
                region
                    .assign_advice(|| "lhs + rhs", config.advice[2], 0, || value)
                    .map(Number)
            },
        )
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(num.0.cell(), config.instance, row)
    }
}

// 实现电路
#[derive(Default, Clone)]
struct PolynomialCircuit<F: Field> {
    a: F,
    b: F,
    c: F,
    d: F,
    x: Value<F>,
    // y: Value<F>,
}

impl<F: Field> Circuit<F> for PolynomialCircuit<F> {
    type Config = PolynomialConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        PolynomialChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let poly_chip = PolynomialChip::<F>::construct(config);

        let x = poly_chip.load_private(layouter.namespace(|| "load x"), self.x)?;
        let a = poly_chip.load_constant(layouter.namespace(|| "load a"), self.a)?;
        let b = poly_chip.load_constant(layouter.namespace(|| "load b"), self.b)?;
        let c = poly_chip.load_constant(layouter.namespace(|| "load c"), self.c)?;
        let d = poly_chip.load_constant(layouter.namespace(|| "load d"), self.d)?;

        // 计算 ax^3
        let x2 = poly_chip.mul(layouter.namespace(|| "x * x"), x.clone(), x.clone())?;
        let x3 = poly_chip.mul(layouter.namespace(|| "x2 * x"), x2.clone(), x.clone())?;
        let ax3 = poly_chip.mul(layouter.namespace(|| "a * x3"), a, x3)?;

        // 计算 bx^2
        let bx2 = poly_chip.mul(layouter.namespace(|| "b * x2"), b, x2.clone().clone())?;

        // 计算 cx
        let cx = poly_chip.mul(layouter.namespace(|| "c * x"), c, x)?;

        // 计算 ax^3 + bx^2 + cx + d
        let ax3_bx2 = poly_chip.add(layouter.namespace(|| "ax3 + bx2"), ax3, bx2)?;
        let ax3_bx2_cx = poly_chip.add(layouter.namespace(|| "ax3_bx2 + cx"), ax3_bx2, cx)?;
        let result = poly_chip.add(layouter.namespace(|| "ax3_bx2_cx + d"), ax3_bx2_cx, d)?;

        // 暴露结果为公共输入
        poly_chip.expose_public(layouter.namespace(|| "expose result"), result, 0)
    }
}


pub struct ProofData {
    proof: Vec<u8>,
    public_inputs: Vec<Fp>,
    vk: VerifyingKey<EqAffine>,
}


pub fn generate_halo2_secret() -> Result<u64, Error> {
    Ok(generate_random_u64_between_10_and_20_digits())
}   

pub fn generate_halo2_proof(secret: u64) -> Result<ProofData, Error> {

    let config = get_config();
    let a = Fp::from(*config.a);
    let b = Fp::from(*config.b);
    let c = Fp::from(*config.c);
    let d = Fp::from(*config.d);
    let x = Fp::from(secret);
    let y = a * x * x * x + b * x * x + c * x + d;

    let params = config.params;

    let public_inputs = vec![y];

    let circuit = PolynomialCircuit {
        a,
        b,
        c,
        d,
        x: Value::known(x),
    };

    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk should not fail");

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&[&public_inputs[..]]],
        &mut rand::thread_rng(),
        &mut transcript,
    ).expect("Proof generation failed");

    let proof = transcript.finalize();

   Ok(ProofData {
        proof,
    public_inputs,
        vk,
    })  
}

pub fn verify_halo2_proof(proof_data: ProofData) -> Result<bool, Error> {
    let ProofData { proof, public_inputs, vk } = proof_data;
   
    let config = get_config();

    let params = config.params;

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let strategy = SingleVerifier::new(&params);

    let result = verify_proof(
        &params,
        &vk,
        strategy,
        &[&[&public_inputs[..]]],
        &mut transcript,
    );
    match result {
        Ok(_) => Ok(true),
        Err(e) => Err(e),
    }
}

pub fn test_proof() -> Result<(), Error> {
    let secret = generate_halo2_secret()?;
    if secret == 0 {
        println!("generate secret failed");
        return Err(Error::from(io::Error::new(io::ErrorKind::Other, "secret is zero")));
    }
    else {
        println!("generate secret success");
    }

    let proof_data = generate_halo2_proof(secret)?;
    if proof_data.proof.len() == 0 {
        println!("generate proof failed");
        return Err(Error::from(io::Error::new(io::ErrorKind::Other, "proof is empty")));
    }
    else {
        println!("generate proof success");
    }

    match verify_halo2_proof(proof_data) {
        Ok(_) => println!("verify proof success"),
        Err(e) => println!("verify proof failed: {:?}", e),
    }

    Ok(())
}

pub fn test_batch_proof(n: u64) -> Result<(), Error> {
    let mut success = 0;
    let mut failed = 0;
    for _ in 0..n {
        let secret = generate_halo2_secret()?;
        if secret > 0 {
            success += 1;
        } else {
            failed += 1;
        }

        let proof_data = generate_halo2_proof(secret)?;
        if proof_data.proof.len() > 0 {
            success += 1;
        } else {
            failed += 1;
        }

        match verify_halo2_proof(proof_data) {
            Ok(true) => success += 1,
            Ok(false) => failed += 1,
            Err(e) => return Err(e.into()),
        }
    }
    println!("success: {}", success);
    println!("failed: {}", failed);
    Ok(())
}
