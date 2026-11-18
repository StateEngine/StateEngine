//! Ordered SQL shared by schema generation and in-place upgrades.
/// Ordered steps; each runs only above the store's current version.
pub(crate) struct Step {
    pub(crate) version: u32,
    pub(crate) sql: &'static str,
    pub(crate) table_rebuild: bool,
}
pub(crate) const STEPS: [Step; 14] = [
    Step {
        version: 2,
        sql: include_str!("../migrations/002.sql"),
        table_rebuild: false,
    },
    Step {
        version: 3,
        sql: include_str!("../migrations/003.sql"),
        table_rebuild: false,
    },
    Step {
        version: 4,
        sql: include_str!("../migrations/004.sql"),
        table_rebuild: false,
    },
    Step {
        version: 5,
        sql: include_str!("../migrations/005.sql"),
        table_rebuild: false,
    },
    Step {
        version: 6,
        sql: include_str!("../migrations/006.sql"),
        table_rebuild: false,
    },
    Step {
        version: 7,
        sql: include_str!("../migrations/007.sql"),
        table_rebuild: false,
    },
    Step {
        version: 8,
        sql: include_str!("../migrations/008.sql"),
        table_rebuild: true,
    },
    Step {
        version: 9,
        sql: include_str!("../migrations/009.sql"),
        table_rebuild: true,
    },
    Step {
        version: 10,
        sql: include_str!("../migrations/010.sql"),
        table_rebuild: false,
    },
    Step {
        version: 11,
        sql: include_str!("../migrations/011.sql"),
        table_rebuild: false,
    },
    Step {
        version: 12,
        sql: include_str!("../migrations/012.sql"),
        table_rebuild: false,
    },
    Step {
        version: 13,
        sql: include_str!("../migrations/013.sql"),
        table_rebuild: true,
    },
    Step {
        version: 14,
        sql: include_str!("../migrations/014.sql"),
        table_rebuild: false,
    },
    Step {
        version: 15,
        sql: include_str!("../migrations/015.sql"),
        table_rebuild: false,
    },
];
