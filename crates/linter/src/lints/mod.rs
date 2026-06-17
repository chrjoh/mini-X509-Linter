//! Built-in lint implementations, grouped by the authority they enforce.
//!
//! Each submodule contains lints from one [`RuleSource`](crate::RuleSource)
//! family. The first family is [`hygiene`], for checks that are good practice
//! but not mandated by a specific standard.

pub mod cabf_br;
pub mod hygiene;
pub mod rfc5280;
