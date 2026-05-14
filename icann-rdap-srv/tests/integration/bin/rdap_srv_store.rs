#![allow(non_snake_case)]

use test_dir::DirBuilder;

use crate::test_jig::RdapSrvStoreTestJig;

#[test]
fn GIVEN_source_dir_same_as_data_dir_WHEN_invoked_THEN_error() {
    // GIVEN
    let mut test_jig = RdapSrvStoreTestJig::new();

    // WHEN
    test_jig.cmd.arg(test_jig.data_dir.root());

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}

#[test]
fn GIVEN_delete_file_option_WHEN_invoked_THEN_delete_list_and_update_flag_are_written() {
    // GIVEN
    let mut test_jig = RdapSrvStoreTestJig::new();

    // WHEN
    test_jig.cmd.arg("--delete-file").arg("deleted.json");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
    assert_eq!(
        std::fs::read_to_string(test_jig.data_dir.path("delete.list"))
            .expect("reading delete.list")
            .trim(),
        "deleted.json"
    );
    assert!(test_jig.data_dir.path("update").exists());
}

#[test]
fn GIVEN_same_file_in_update_and_delete_WHEN_invoked_THEN_error() {
    // GIVEN
    let mut test_jig = RdapSrvStoreTestJig::new();
    std::fs::write(test_jig.data_dir.path("shared.json"), "{}").expect("writing shared.json");

    // WHEN
    test_jig
        .cmd
        .arg("--update-file")
        .arg("shared.json")
        .arg("--delete-file")
        .arg("shared.json");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}
