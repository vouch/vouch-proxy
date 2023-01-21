# Setting up a Development Environment

## Running Tests 

```bash
 export VOUCH_ROOT=`pwd` # if not using GOPATH
 ./do.sh test
```

After running these tests manually once (which creates a test key pair), it is possible to run the tests with VSCode Test Explorer.

To get it to work, we must set some environment variables in `.vscode/settings.json` which otherwise would be set by `do.sh`:

```json
{
    "go.testEnvVars": {
        "VOUCH_ROOT": "${workspaceFolder}",
        "VOUCH_CONFIG": "${workspaceFolder}/config/testing/test_config.yml",
        "TEST_PRIVATE_KEY_FILE": "${workspaceFolder}/config/testing/rsa.key",
        "TEST_PUBLIC_KEY_FILE": "${workspaceFolder}/config/testing/rsa.pub",
    }
}
```

### Contributing to Vouch Proxy by submitting a Pull Request

**_I really love Vouch Proxy! I wish it did XXXX..._**

That's really wonderful and contributions are greatly appreciated. However, please search through the existing issues, both open and closed, to look for any prior work or conversation. Then please make a proposal before we all spend valuable time considering and integrating a new feature.

Code contributions should..

- generally be discussed beforehand in a GitHub issue
- include unit tests and in some cases end-to-end tests
- be formatted with `go fmt`, checked with `go vet` and other common go tools
- accomodate configuration via `config.yml` as well as `ENVIRONMENT_VARIABLEs`.
- not break existing setups without a clear reason (usually security related)
- include an entry at the top of CHANGELOG.md in the **Unreleased** section

For larger contributions or code related to a platform that we don't currently support we will ask you to commit to supporting the feature for an agreed upon period. Invariably someone will pop up here with a question and we want to be able to support these requests.

**Thank you to all of the contributors that have provided their time and effort and thought to improving VP.**
