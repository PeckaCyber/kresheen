from click.testing import CliRunner

from kresheen.cli.main import cli
from kresheen.dashboard.auth import MIN_PASSWORD_LENGTH
from kresheen.storage.sql_repo import SQLRepository


def test_first_user_is_always_owner_regardless_of_role_flag(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    runner = CliRunner()

    result = runner.invoke(
        cli, ["create-user", "--db", db_url, "--email", "first@example.com", "--role", "member"]
    )

    assert result.exit_code == 0, result.output
    assert "role=owner" in result.output
    user = SQLRepository(db_url).get_user_by_email("first@example.com")
    assert user is not None
    assert user.role == "owner"


def test_second_user_honors_requested_role(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    runner = CliRunner()
    runner.invoke(cli, ["create-user", "--db", db_url, "--email", "first@example.com"])

    result = runner.invoke(
        cli, ["create-user", "--db", db_url, "--email", "second@example.com", "--role", "member"]
    )

    assert result.exit_code == 0, result.output
    user = SQLRepository(db_url).get_user_by_email("second@example.com")
    assert user.role == "member"


def test_create_user_generates_a_password_when_not_given(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    runner = CliRunner()

    result = runner.invoke(cli, ["create-user", "--db", db_url, "--email", "first@example.com"])

    assert result.exit_code == 0, result.output
    assert "KRESHEEN_USER_PASSWORD=" in result.output


def test_create_user_rejects_duplicate_email(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    runner = CliRunner()
    runner.invoke(cli, ["create-user", "--db", db_url, "--email", "dup@example.com"])

    result = runner.invoke(cli, ["create-user", "--db", db_url, "--email", "dup@example.com"])

    assert result.exit_code != 0
    assert "already exists" in result.output


def test_create_user_rejects_a_short_password(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    runner = CliRunner()

    result = runner.invoke(
        cli, ["create-user", "--db", db_url, "--email", "a@example.com", "--password", "x" * (MIN_PASSWORD_LENGTH - 1)]
    )

    assert result.exit_code != 0
    assert f"at least {MIN_PASSWORD_LENGTH} characters" in result.output
    assert SQLRepository(db_url).get_user_by_email("a@example.com") is None


def test_create_user_accepts_a_password_of_the_minimum_length(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    runner = CliRunner()

    result = runner.invoke(
        cli, ["create-user", "--db", db_url, "--email", "a@example.com", "--password", "x" * MIN_PASSWORD_LENGTH]
    )

    assert result.exit_code == 0, result.output


def test_create_user_help_has_no_stray_punctuation():
    result = CliRunner().invoke(cli, ["create-user", "--help"])

    assert result.exit_code == 0
    assert f"at least {MIN_PASSWORD_LENGTH} characters" in result.output
    assert " ." not in result.output
