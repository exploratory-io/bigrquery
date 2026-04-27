test_that("bq_user() works", {
  skip_if_no_auth()
  expect_match(bq_user(), "@.*[.]iam[.]gserviceaccount[.]com")
})

test_that("useful error if can't auth", {
  local_mocked_bindings(token_fetch = function(...) NULL)

  expect_snapshot(bq_auth(), error = TRUE)
})

test_that("bq_auth_configure checks its inputs", {
  expect_snapshot(error = TRUE, {
    bq_auth_configure(1, 1)
    bq_auth_configure(client = 1)
    bq_auth_configure(path = 1)
  })
})

# Exploratory fork: token-refresh bypass tests --------------------------------

test_that("bq_token() returns add_headers (Bearer) when cred has access_token", {
  fake_token <- structure(
    list(credentials = list(access_token = "ya29.fake-access-token")),
    class = c("Token2.0", "Token", "R6")
  )
  local_mocked_bindings(bq_has_token = function() TRUE)
  withr::local_environment({
    bigrquery_env <- asNamespace("bigrquery")
    old_cred <- bigrquery_env$.auth$cred
    on.exit(bigrquery_env$.auth$cred <- old_cred)
    bigrquery_env$.auth$cred <- fake_token

    out <- bq_token()
    expect_s3_class(out, "request")
    # add_headers result has the header in $headers; config(token=) does not.
    # headers populated by add_headers
    expect_match(out$headers[["Authorization"]], "^Bearer ya29\\.fake-access-token$")
    # Critical: must NOT carry a refreshable token through httr's options
    expect_null(out$auth_token)  # httr::config(token=) sets $auth_token
  })
})

test_that("bq_token() falls back to httr::config when cred has no access_token", {
  fake_token <- structure(list(credentials = list()), class = c("Token2.0", "Token", "R6"))
  local_mocked_bindings(bq_has_token = function() TRUE)
  withr::local_environment({
    bigrquery_env <- asNamespace("bigrquery")
    old_cred <- bigrquery_env$.auth$cred
    on.exit(bigrquery_env$.auth$cred <- old_cred)
    bigrquery_env$.auth$cred <- fake_token

    out <- bq_token()
    expect_s3_class(out, "request")
    # config(token=) populates $options$token; add_headers does not.
    expect_false(is.null(out$auth_token))
  })
})
