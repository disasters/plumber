#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum Chain<A,B> {
    Args(A),
    Ret(B),
}

impl <A,B> Chain<A,B> {
    pub fn map<F: FnOnce(A) -> Chain<A,B>>(self, f: F) -> Chain<A, B> {
        match self {
            Chain::Args(a) => f(a),
            Chain::Ret(b) => Chain::Ret(b),
        }
    }

    pub fn is_done(self) -> bool {
        match self {
            Chain::Args(_) => false,
            Chain::Ret(_) => true,
        }
    }

    pub fn unwrap(self) -> B {
        match self {
            Chain::Args(_) => panic!("Called unwrap on Chain::Args."),
            Chain::Ret(b) => b,
        }
    }

    pub fn unwrap_or<F: FnOnce(A) -> B>(self, f: F) -> B {
        match self {
            Chain::Args(a) => f(a),
            Chain::Ret(b) => b,
        }
    }

    pub fn unwrap_or_else(self, b: B) -> B {
        match self {
            Chain::Args(_) => b,
            Chain::Ret(d) => d,
        }
    }
}

#[test]
fn test_chain() {
    assert!(Chain::Args("yo").map( |_| {
        Chain::Args("hey")
    }).map( |_| {
        Chain::Ret("the deed is done")
    }).map( |_| {
        Chain::Ret("wha??")
    }).unwrap() == "the deed is done");

    assert!(Chain::Args("yo").map( |_| {
        Chain::Args("hey")
    }).unwrap_or( |_| {
        "use this instead"
    }) == "use this instead");

    assert!(Chain::Args("yo").map( |_| {
        Chain::Args("hey")
    }).unwrap_or_else(
        "use this instead"
    ) == "use this instead");
}
