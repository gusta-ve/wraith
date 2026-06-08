from wraith.phases.injection import REDIRECT_PARAMS, looks_like_sql_error


def test_sql_error_detection():
    assert looks_like_sql_error("You have an error in your SQL syntax; near ''") is True
    assert looks_like_sql_error("Warning: mysqli_query()") is True
    assert looks_like_sql_error("ORA-00933: SQL command not properly ended") is True
    assert looks_like_sql_error("just a normal page") is False


def test_redirect_params():
    assert {"url", "next", "redirect"} <= REDIRECT_PARAMS
