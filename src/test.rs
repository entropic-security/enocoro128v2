#![deny(warnings)]

// Note these imports are only for testing, not required/linked for the library
extern crate std;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::vec::Vec;
use std::{env, format, println};

use super::*;

// TODO: check for consistent comments

pub const TV_SIZE_BYTE: usize = 1024;
pub const ROUND_START: i64 = -97;
pub const ROUND_END: i64 = 1023;

// TEST VECTOR FILE LOAD/PARSE #########################################################################################

// Test Vector: state, buffer tuple
#[derive(Debug, PartialEq, Eq, Hash)]
struct RoundData {
    state: [u8; E128_STATE_SIZE_BYTE],
    buf: [u8; E128_BUF_SIZE_BYTE],
}

// Test: test vectors by round, all same key and IV
struct Test {
    key: [u8; E128_KEY_SIZE_BYTE],
    iv: [u8; E128_IV_SIZE_BYTE],
    tv: [u8; TV_SIZE_BYTE],
    rounds: HashMap<i64, RoundData>,
}

impl Test {
    pub fn new() -> Test {
        Test {
            key: [0; E128_KEY_SIZE_BYTE],
            iv: [0; E128_IV_SIZE_BYTE],
            tv: [0; TV_SIZE_BYTE],
            rounds: HashMap::new(),
        }
    }
}

// Possible states for Test Collector
#[derive(Debug, PartialEq, Eq, Hash)]
enum TestCollectorState {
    Idle,
    InputRound,
    InputState,
    InputBuffer,
    InputKey,
    InputIV,
    InputTV,
}

// Test Collector: parses file line-by-line to collect Tests
struct TestCollector {
    collect_state: TestCollectorState,
    tests: Vec<Test>,
    curr_round: i64,
    curr_state: Vec<u8>,
    curr_buf: Vec<u8>,
    curr_key: Vec<u8>,
    curr_iv: Vec<u8>,
    curr_tv: Vec<u8>,
    round_set: bool,
}

impl TestCollector {
    const DELIM_ROUND: &'static str = "round = ";
    const DELIM_STATE: &'static str = "state : ";
    const DELIM_BUFFER: &'static str = "buffer : ";
    const DELIM_KEY: &'static str = "Key        :";
    const DELIM_IV: &'static str = "IV         :";
    const DELIM_TV: &'static str = "Test Vector:";

    // Public APIs -----------------------------------------------------------------------------------------------------

    pub fn new() -> TestCollector {
        let mut tc = TestCollector {
            collect_state: TestCollectorState::Idle,
            tests: Vec::new(),
            curr_round: 0,
            curr_state: Vec::new(),
            curr_buf: Vec::new(),
            curr_key: Vec::new(),
            curr_iv: Vec::new(),
            curr_tv: Vec::new(),
            round_set: false,
        };

        tc.tests.push(Test::new());

        tc
    }

    // TODO: verify logic
    pub fn process_line(&mut self, line: &str) {
        if line.contains(TestCollector::DELIM_ROUND) {
            self.collect_state = TestCollectorState::InputRound;
        } else if line.contains(TestCollector::DELIM_STATE) {
            self.collect_state = TestCollectorState::InputState;
        } else if line.contains(TestCollector::DELIM_BUFFER) {
            self.collect_state = TestCollectorState::InputBuffer;
        } else if line.contains(TestCollector::DELIM_KEY) {
            self.collect_state = TestCollectorState::InputKey;
        } else if line.contains(TestCollector::DELIM_IV) {
            self.collect_state = TestCollectorState::InputIV;
        } else if line.contains(TestCollector::DELIM_TV) {
            self.collect_state = TestCollectorState::InputTV;
        }

        self.collect_data(line);
        self.commit_data();
    }

    // Private APIs ----------------------------------------------------------------------------------------------------

    fn collect_data(&mut self, line: &str) {
        match self.collect_state {
            TestCollectorState::InputRound => {
                self.curr_round = line
                    .trim()
                    .trim_start_matches(TestCollector::DELIM_ROUND)
                    .parse()
                    .unwrap();
                self.round_set = true;
            }
            TestCollectorState::InputState => {
                self.curr_state.extend(
                    TestCollector::parse_str_hex_bytes(line, TestCollector::DELIM_STATE)
                        .iter()
                        .cloned(),
                );
            }
            TestCollectorState::InputBuffer => {
                self.curr_buf.extend(
                    TestCollector::parse_str_hex_bytes(line, TestCollector::DELIM_BUFFER)
                        .iter()
                        .cloned(),
                );
            }
            TestCollectorState::InputKey => {
                self.curr_key.extend(
                    TestCollector::parse_str_hex_bytes(line, TestCollector::DELIM_KEY)
                        .iter()
                        .cloned(),
                );
            }
            TestCollectorState::InputIV => {
                self.curr_iv.extend(
                    TestCollector::parse_str_hex_bytes(line, TestCollector::DELIM_IV)
                        .iter()
                        .cloned(),
                );
            }
            TestCollectorState::InputTV => {
                self.curr_tv.extend(
                    TestCollector::parse_str_hex_bytes(line, TestCollector::DELIM_TV)
                        .iter()
                        .cloned(),
                );
            }
            _ => {
                return;
            }
        }
    }

    fn commit_data(&mut self) {
        if self.round_set
            && (self.curr_state.len() >= E128_STATE_SIZE_BYTE)
            && (self.curr_buf.len() >= E128_BUF_SIZE_BYTE)
        {
            self.commit_round();
            self.reset_state_partial();
        }

        if (self.curr_key.len() >= E128_KEY_SIZE_BYTE)
            && (self.curr_iv.len() >= E128_IV_SIZE_BYTE)
            && (self.curr_tv.len() >= TV_SIZE_BYTE)
        {
            self.commit_test();
            self.reset_state_full();
        }
    }

    // Convert string of space-delimited hex bytes to vector of u8
    fn parse_str_hex_bytes(line: &str, prefix: &str) -> Vec<u8> {
        let data = line.trim().trim_start_matches(prefix);

        if data.is_empty() {
            return Vec::new();
        }

        data.split(" ")
            .map(|x| u8::from_str_radix(x.trim_start_matches("0x"), 16).unwrap())
            .collect()
    }

    // Reset after round triplet (round number, state, buffer) commit
    fn reset_state_partial(&mut self) {
        self.collect_state = TestCollectorState::Idle;
        self.round_set = false;
        self.curr_round = 0;
        self.curr_state.clear();
        self.curr_buf.clear();
    }

    // Reset after test (rounds, key, IV, TV) commit
    fn reset_state_full(&mut self) {
        self.reset_state_partial();
        self.curr_key.clear();
        self.curr_iv.clear();
        self.curr_tv.clear();
    }

    // Commit RoundData to Test's hashmap
    fn commit_round(&mut self) {
        let mut rd = RoundData {
            state: [0; E128_STATE_SIZE_BYTE],
            buf: [0; E128_BUF_SIZE_BYTE],
        };

        assert_eq!(rd.state.len(), self.curr_state.len());
        assert_eq!(rd.buf.len(), self.curr_buf.len());
        rd.state[..].copy_from_slice(&self.curr_state[..]);
        rd.buf[..].copy_from_slice(&self.curr_buf[..]);

        self.tests
            .last_mut()
            .unwrap()
            .rounds
            .insert(self.curr_round, rd);

        println!(
            "[Test: {}][Round: {}] -> {:?}",
            self.tests.len(),
            self.curr_round,
            self.tests
                .last()
                .unwrap()
                .rounds
                .get(&self.curr_round)
                .unwrap(),
        );
    }

    // Commit Test to TestCollector's Vec
    fn commit_test(&mut self) {
        let curr_test_num = self.tests.len();
        let curr_test = self.tests.last_mut().unwrap();

        assert_eq!(curr_test.key.len(), self.curr_key.len());
        assert_eq!(curr_test.iv.len(), self.curr_iv.len());
        assert_eq!(curr_test.tv.len(), self.curr_tv.len());

        curr_test.key[..].copy_from_slice(&self.curr_key);
        curr_test.iv[..].copy_from_slice(&self.curr_iv);
        curr_test.tv[..].copy_from_slice(&self.curr_tv);

        println!(
            "\n[Test: {}]: Key: {:?}, IV: {:?}, Test Vector: {:?}\n",
            curr_test_num,
            curr_test.key,
            curr_test.iv,
            &curr_test.tv[..]
        );

        self.tests.push(Test::new());
    }

    // Check that all round numbers in an inclusive range are present for all collected Tests
    fn verify_finalize(&mut self, start_round_num: i64, end_round_num: i64) -> bool {
        // Strip test allocated after final commit
        self.tests.retain(|t| !t.rounds.is_empty());

        // Wipe temporaries from any potential uncompleted test commit
        self.reset_state_full();

        // Verify all collected tests contain complete round range
        for t in &self.tests {
            for k in start_round_num..=end_round_num {
                if !t.rounds.contains_key(&k) {
                    return false;
                }
            }
        }

        true
    }
}

// TEST VECTOR VALIDATION ##############################################################################################

fn test_collector_load() -> TestCollector {
    let base = env::current_dir().unwrap();
    let target = base.join("tests").join("official_test_vectors.txt");
    let file = File::open(target).unwrap();
    let reader = BufReader::new(file);
    let mut tc = TestCollector::new();

    for (idx, line) in reader.lines().enumerate() {
        let err_msg = format!("Unable to read line {}", idx);
        let line = line.expect(&err_msg);
        tc.process_line(&line);
    }

    assert!(tc.verify_finalize(ROUND_START, ROUND_END));

    tc
}

#[inline(always)]
fn internals_in_lockstep(e128: &Enocoro128, rd: &RoundData) -> bool {
    ((e128.state == rd.state) && (e128.buf == rd.buf))
}

// Used for testing to inspect state during initialization rounds (occur within constructor)
fn bypass_constructor(key: &[u8], iv: &[u8]) -> Enocoro128 {
    let mut e128 = Enocoro128 {
        key: [0; E128_KEY_SIZE_BYTE],
        iv: [0; E128_IV_SIZE_BYTE],
        state: [0; E128_STATE_SIZE_BYTE],
        buf: [0; E128_BUF_SIZE_BYTE],
        top: 0,
    };

    e128.key[..].copy_from_slice(&key);
    e128.iv[..].copy_from_slice(&iv);
    e128.buf[0..E128_KEY_SIZE_BYTE].copy_from_slice(&e128.key);
    e128.buf[E128_KEY_SIZE_BYTE..(E128_KEY_SIZE_BYTE + E128_IV_SIZE_BYTE)]
        .copy_from_slice(&e128.iv);
    e128.buf[(E128_KEY_SIZE_BYTE + E128_IV_SIZE_BYTE)..].copy_from_slice(&E128_BUF_TAIL_INIT);
    e128.state[..].copy_from_slice(&E128_STATE_INIT);

    e128
}

// TODO: solution to not load test_collector twice

#[test]
fn test_internal_states() {
    let test_collector = test_collector_load();

    for test in test_collector.tests {
        let mut ctr = 0x1;
        let mut e128 = bypass_constructor(&test.key, &test.iv);

        // Initialization states
        assert!(internals_in_lockstep(
            &e128,
            test.rounds.get(&ROUND_START).unwrap()
        ));
        for round_num in (ROUND_START + 1)..0 {
            let round_data = test.rounds.get(&round_num).unwrap();
            e128.buf[(e128.top.wrapping_add(K128_SHIFT) & 0x1f) as usize] ^= ctr;
            ctr = XTIME[ctr as usize];
            e128.next128();
            assert!(internals_in_lockstep(&e128, round_data));
        }

        // Post-initialization states
        for round_num in 0..=ROUND_END {
            let round_data = test.rounds.get(&round_num).unwrap();
            e128.next128();
            assert!(internals_in_lockstep(&e128, round_data));
        }
    }
}

#[test]
fn test_output() {
    let test_collector = test_collector_load();

    for test in test_collector.tests {
        let mut test_vector = [0; TV_SIZE_BYTE];
        Enocoro128::encrypt_static(&test.key, &test.iv, &mut test_vector);
        assert!(test.tv.iter().zip(test_vector.iter()).all(|(a, b)| a == b));
    }
}
