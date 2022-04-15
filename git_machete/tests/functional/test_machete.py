import io
import json
import os
import random
import re
import string
import subprocess
import sys
import textwrap
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http import HTTPStatus
from typing import Any, Dict, Iterable, List, Optional, Union
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import ParseResult, parse_qs, urlparse

from git_machete import cli
from git_machete.docs import long_docs
from git_machete.exceptions import MacheteException
from git_machete.git_operations import (FullCommitHash, GitContext,
                                        LocalBranchShortName)
from git_machete.github import get_parsed_github_remote_url
from git_machete.options import CommandLineOptions
from git_machete.utils import dim

cli_opts: CommandLineOptions = CommandLineOptions()
git: GitContext = GitContext()

FAKE_GITHUB_REMOTE_PATTERNS = ['(.*)/(.*)']


def popen(command: str) -> str:
    with os.popen(command) as process:
        return process.read().strip()


def get_current_commit_hash() -> FullCommitHash:
    """Returns hash of a commit of the current branch head."""
    return FullCommitHash.of(popen("git rev-parse HEAD"))


def mock_exit_script(status_code: Optional[int] = None, error: Optional[BaseException] = None) -> None:
    if error:
        raise error
    else:
        sys.exit(status_code)


def mock_fetch_ref(cls: Any, remote: str, ref: str) -> None:
    branch: LocalBranchShortName = LocalBranchShortName.of(ref[ref.index(':') + 1:])
    git.create_branch(branch, get_current_commit_hash(), switch_head=True)


def mock_run_cmd(cmd: str, *args: str, **kwargs: Any) -> int:
    completed_process: subprocess.CompletedProcess[bytes] = subprocess.run(
        [cmd] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    exit_code: int = completed_process.returncode

    if exit_code != 0:
        print(dim(f"<exit code: {exit_code}>\n"), file=sys.stderr)
    return completed_process.returncode


def mock_run_cmd_and_forward_stdout(cmd: str, *args: str, **kwargs: Any) -> int:
    completed_process: subprocess.CompletedProcess[bytes] = subprocess.run(
        [cmd] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, ** kwargs)
    print(completed_process.stdout.decode('utf-8'))
    exit_code: int = completed_process.returncode
    if exit_code != 0:
        print(dim(f"<exit code: {exit_code}>\n"), file=sys.stderr)
    return exit_code


def mock_derive_current_user_login() -> str:
    return "very_complex_user_token"


def mock_ask_if(*args: str, **kwargs: Any) -> str:
    return 'y'


def mock__get_github_token() -> Optional[str]:
    return None


def mock__get_github_token_fake() -> Optional[str]:
    return 'token'


def mock_should_perform_interactive_slide_out(cmd: str) -> bool:
    return True


class FakeCommandLineOptions(CommandLineOptions):
    def __init__(self) -> None:
        super().__init__()
        self.opt_no_interactive_rebase: bool = True
        self.opt_yes: bool = True


class MockGitHubAPIState:
    def __init__(self, pulls: List[Dict[str, Any]], issues: List[Dict[str, Any]] = None) -> None:
        self.pulls: List[Dict[str, Any]] = pulls
        self.user: Dict[str, str] = {'login': 'other_user', 'type': 'User', 'company': 'VirtusLab'}  # login must be different from the one used in pull requests, otherwise pull request author will not be annotated
        self.issues: List[Dict[str, Any]] = issues or []

    def new_request(self) -> "MockGitHubAPIRequest":
        return MockGitHubAPIRequest(self)

    def get_issue(self, issue_no: str) -> Optional[Dict[str, Any]]:
        for issue in self.issues:
            if issue['number'] == issue_no:
                return issue
        return None

    def get_pull(self, pull_no: str) -> Optional[Dict[str, Any]]:
        for pull in self.pulls:
            if pull['number'] == pull_no:
                return pull
        return None


class MockGitHubAPIResponse:
    def __init__(self, status_code: int, response_data: Union[List[Dict[str, Any]], Dict[str, Any]]) -> None:
        self.response_data: Union[List[Dict[str, Any]], Dict[str, Any]] = response_data
        self.status_code: int = status_code

    def read(self) -> bytes:
        return json.dumps(self.response_data).encode()


class MockGitHubAPIRequest:
    def __init__(self, github_api_state: MockGitHubAPIState) -> None:
        self.github_api_state: MockGitHubAPIState = github_api_state

    def __call__(self, url: str, headers: Dict[str, str] = None, data: Union[str, bytes, None] = None, method: str = '') -> "MockGitHubAPIResponse":
        self.parsed_url: ParseResult = urlparse(url, allow_fragments=True)
        self.parsed_query: Dict[str, List[str]] = parse_qs(self.parsed_url.query)
        self.json_data: Union[str, bytes] = data
        self.return_data: Optional[Union[List[Dict[str, Any]], Dict[str, Any]]] = None
        self.headers: Dict[str, str] = headers
        return self.handle_method(method)

    def handle_method(self, method: str) -> "MockGitHubAPIResponse":
        if method == "GET":
            return self.handle_get()
        elif method == "PATCH":
            return self.handle_patch()
        elif method == "POST":
            return self.handle_post()
        else:
            return self.make_response_object(HTTPStatus.METHOD_NOT_ALLOWED, [])

    def handle_get(self) -> "MockGitHubAPIResponse":
        if 'pulls' in self.parsed_url.path:
            full_head_name: Optional[List[str]] = self.parsed_query.get('head')
            number: Optional[str] = self.find_number(self.parsed_url.path, 'pulls')
            if number:
                for pr in self.github_api_state.pulls:
                    if pr['number'] == number:
                        return self.make_response_object(HTTPStatus.OK, pr)
                return self.make_response_object(HTTPStatus.NOT_FOUND, [])
            elif full_head_name:
                head: str = full_head_name[0].split(':')[1]
                for pr in self.github_api_state.pulls:
                    if pr['head']['ref'] == head:
                        return self.make_response_object(HTTPStatus.OK, [pr])
                return self.make_response_object(HTTPStatus.NOT_FOUND, [])
            else:
                return self.make_response_object(HTTPStatus.OK, [pull for pull in self.github_api_state.pulls if pull['state'] == 'open'])
        elif self.parsed_url.path.endswith('user'):
            return self.make_response_object(HTTPStatus.OK, self.github_api_state.user)
        else:
            return self.make_response_object(HTTPStatus.NOT_FOUND, [])

    def handle_patch(self) -> "MockGitHubAPIResponse":
        if 'issues' in self.parsed_url.path:
            return self.update_issue()
        elif 'pulls' in self.parsed_url.path:
            return self.update_pull_request()
        else:
            return self.make_response_object(HTTPStatus.NOT_FOUND, [])

    def handle_post(self) -> "MockGitHubAPIResponse":
        assert not self.parsed_query
        if 'issues' in self.parsed_url.path:
            return self.update_issue()
        elif 'pulls' in self.parsed_url.path:
            return self.update_pull_request()
        else:
            return self.make_response_object(HTTPStatus.NOT_FOUND, [])

    def update_pull_request(self) -> "MockGitHubAPIResponse":
        pull_no: str = self.find_number(self.parsed_url.path, 'pulls')
        if not pull_no:
            if self.is_pull_created():
                return self.make_response_object(HTTPStatus.UNPROCESSABLE_ENTITY, {'message': 'Validation Failed', 'errors': [
                    {'message': f'A pull request already exists for test_repo:{json.loads(self.json_data)["head"]}.'}]})
            return self.create_pull_request()
        pull: Dict[str, Any] = self.github_api_state.get_pull(pull_no)
        return self.fill_pull_request_data(json.loads(self.json_data), pull)

    def create_pull_request(self) -> "MockGitHubAPIResponse":
        pull = {'number': self.get_next_free_number(self.github_api_state.pulls),
                'user': {'login': 'github_user'},
                'html_url': 'www.github.com',
                'state': 'open',
                'head': {'ref': "", 'repo': {'full_name': 'testing:checkout_prs', 'html_url': popen("mktemp -d")}},
                'base': {'ref': ""}}
        return self.fill_pull_request_data(json.loads(self.json_data), pull)

    def fill_pull_request_data(self, data: Dict[str, Any], pull: Dict[str, Any]) -> "MockGitHubAPIResponse":
        index = self.get_index_or_none(pull, self.github_api_state.issues)
        for key in data.keys():
            if key in ('base', 'head'):
                pull[key]['ref'] = json.loads(self.json_data)[key]
            else:
                pull[key] = json.loads(self.json_data)[key]
        if index:
            self.github_api_state.pulls[index] = pull
        else:
            self.github_api_state.pulls.append(pull)
        return self.make_response_object(HTTPStatus.CREATED, pull)

    def update_issue(self) -> "MockGitHubAPIResponse":
        issue_no: str = self.find_number(self.parsed_url.path, 'issues')
        if not issue_no:
            return self.create_issue()
        issue: Dict[str, Any] = self.github_api_state.get_issue(issue_no)
        return self.fill_issue_data(json.loads(self.json_data), issue)

    def create_issue(self) -> "MockGitHubAPIResponse":
        issue = {'number': self.get_next_free_number(self.github_api_state.issues)}
        return self.fill_issue_data(json.loads(self.json_data), issue)

    def fill_issue_data(self, data: Dict[str, Any], issue: Dict[str, Any]) -> "MockGitHubAPIResponse":
        index = self.get_index_or_none(issue, self.github_api_state.issues)
        for key in data.keys():
            issue[key] = data[key]
        if index is not None:
            self.github_api_state.issues[index] = issue
        else:
            self.github_api_state.issues.append(issue)
        return self.make_response_object(HTTPStatus.CREATED, issue)

    def is_pull_created(self) -> bool:
        deserialized_json_data = json.loads(self.json_data)
        head: str = deserialized_json_data['head']
        base: str = deserialized_json_data['base']
        for pull in self.github_api_state.pulls:
            pull_head: str = pull['head']['ref']
            pull_base: str = pull['base']['ref']
            if (head, base) == (pull_head, pull_base):
                return True
        return False

    @staticmethod
    def get_index_or_none(entity: Dict[str, Any], base: List[Dict[str, Any]]) -> Optional[int]:
        try:
            return base.index(entity)
        except ValueError:
            return None

    @staticmethod
    def make_response_object(status_code: int, response_data: Union[List[Dict[str, Any]], Dict[str, Any]]) -> "MockGitHubAPIResponse":
        return MockGitHubAPIResponse(status_code, response_data)

    @staticmethod
    def find_number(url: str, entity: str) -> Optional[str]:
        m = re.search(f'{entity}/(\\d+)', url)
        if m:
            return m.group(1)
        return None

    @staticmethod
    def get_next_free_number(entities: List[Dict[str, Any]]) -> str:
        numbers = [int(item['number']) for item in entities]
        return str(max(numbers) + 1)


class MockHTTPError(HTTPError):
    from email.message import Message

    def __init__(self, url: str, code: int, msg: Any, hdrs: Message, fp: Any) -> None:
        super().__init__(url, code, msg, hdrs, fp)
        self.msg = msg

    def read(self, n: int = 1) -> bytes:
        return json.dumps(self.msg).encode()


class MockContextManager:
    def __init__(self, obj: MockGitHubAPIResponse) -> None:
        self.obj = obj

    def __enter__(self) -> MockGitHubAPIResponse:
        if self.obj.status_code == HTTPStatus.NOT_FOUND:
            raise HTTPError(None, 404, 'Not found', None, None)
        elif self.obj.status_code == HTTPStatus.UNPROCESSABLE_ENTITY:
            raise MockHTTPError(None, 422, self.obj.response_data, None, None)
        return self.obj

    def __exit__(self, *args: Any) -> None:
        pass


class GitRepositorySandbox:
    second_remote_path = popen("mktemp -d")

    def __init__(self) -> None:
        self.remote_path = popen("mktemp -d")
        self.local_path = popen("mktemp -d")

    def execute(self, command: str) -> "GitRepositorySandbox":
        subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
        return self

    def new_repo(self, *args: str) -> "GitRepositorySandbox":
        os.chdir(args[0])
        opts = args[1:]
        self.execute(f"git init {' '.join(opts)}")
        return self

    def new_branch(self, branch_name: str) -> "GitRepositorySandbox":
        self.execute(f"git checkout -b {branch_name}")
        return self

    def new_root_branch(self, branch_name: str) -> "GitRepositorySandbox":
        self.execute(f"git checkout --orphan {branch_name}")
        return self

    def check_out(self, branch: str) -> "GitRepositorySandbox":
        self.execute(f"git checkout {branch}")
        return self

    def commit(self, message: str = "Some commit message.") -> "GitRepositorySandbox":
        f = "%s.txt" % "".join(random.choice(string.ascii_letters) for _ in range(20))
        self.execute(f"touch {f}")
        self.execute(f"git add {f}")
        self.execute(f'git commit -m "{message}"')
        return self

    def commit_amend(self, message: str) -> "GitRepositorySandbox":
        self.execute(f'git commit --amend -m "{message}"')
        return self

    def push(self) -> "GitRepositorySandbox":
        branch = popen("git symbolic-ref -q --short HEAD")
        self.execute(f"git push -u origin {branch}")
        return self

    def sleep(self, seconds: int) -> "GitRepositorySandbox":
        time.sleep(seconds)
        return self

    def reset_to(self, revision: str) -> "GitRepositorySandbox":
        self.execute(f'git reset --keep "{revision}"')
        return self

    def delete_branch(self, branch: str) -> "GitRepositorySandbox":
        self.execute(f'git branch -d "{branch}"')
        return self

    def add_remote(self, remote: str, url: str) -> "GitRepositorySandbox":
        self.execute(f'git remote add {remote} {url}')
        return self


class MacheteTester(unittest.TestCase):
    mock_repository_info: Dict[str, str] = {'full_name': 'testing/checkout_prs',
                                            'html_url': 'https://github.com/tester/repo_sandobx.git'}

    @staticmethod
    def adapt(s: str) -> str:
        return textwrap.indent(textwrap.dedent(re.sub(r"\|\n", "| \n", s[1:])), "  ")

    @staticmethod
    def launch_command(*args: str) -> str:
        with io.StringIO() as out:
            with redirect_stdout(out):
                with redirect_stderr(out):
                    cli.launch(list(args))
                    git.flush_caches()
            return out.getvalue()

    @staticmethod
    def rewrite_definition_file(new_body: str) -> None:
        definition_file_path = git.get_main_git_subpath("machete")
        with open(os.path.join(os.getcwd(), definition_file_path), 'w') as def_file:
            def_file.writelines(new_body)

    def assert_command(self, cmds: Iterable[str], expected_result: str, strip_indentation: bool = True) -> None:
        self.assertEqual(self.launch_command(*cmds), self.adapt(expected_result) if strip_indentation else expected_result)

    def setUp(self) -> None:
        # Status diffs can be quite large, default to ~256 lines of diff context
        # https://docs.python.org/3/library/unittest.html#unittest.TestCase.maxDiff
        self.maxDiff = 80 * 256

        self.repo_sandbox = GitRepositorySandbox()

        (
            self.repo_sandbox
            # Create the remote and sandbox repos, chdir into sandbox repo
            .new_repo(self.repo_sandbox.remote_path, "--bare")
            .new_repo(self.repo_sandbox.local_path)
            .execute(f"git remote add origin {self.repo_sandbox.remote_path}")
            .execute('git config user.email "tester@test.com"')
            .execute('git config user.name "Tester Test"')
        )

    def setup_discover_standard_tree(self) -> None:
        (
            self.repo_sandbox.new_branch("root")
            .commit("root")
            .new_branch("develop")
            .commit("develop commit")
            .new_branch("allow-ownership-link")
            .commit("Allow ownership links")
            .push()
            .new_branch("build-chain")
            .commit("Build arbitrarily long chains")
            .check_out("allow-ownership-link")
            .commit("1st round of fixes")
            .check_out("develop")
            .commit("Other develop commit")
            .push()
            .new_branch("call-ws")
            .commit("Call web service")
            .commit("1st round of fixes")
            .push()
            .new_branch("drop-constraint")
            .commit("Drop unneeded SQL constraints")
            .check_out("call-ws")
            .commit("2nd round of fixes")
            .check_out("root")
            .new_branch("master")
            .commit("Master commit")
            .push()
            .new_branch("hotfix/add-trigger")
            .commit("HOTFIX Add the trigger")
            .push()
            .commit_amend("HOTFIX Add the trigger (amended)")
            .new_branch("ignore-trailing")
            .commit("Ignore trailing data")
            .sleep(1)
            .commit_amend("Ignore trailing data (amended)")
            .push()
            .reset_to("ignore-trailing@{1}")
            .delete_branch("root")
        )

        self.launch_command("discover", "-y", "--roots=develop,master")
        self.assert_command(
            ["status"],
            """
            develop
            |
            x-allow-ownership-link (ahead of origin)
            | |
            | x-build-chain (untracked)
            |
            o-call-ws (ahead of origin)
              |
              x-drop-constraint (untracked)

            master
            |
            o-hotfix/add-trigger (diverged from origin)
              |
              o-ignore-trailing * (diverged from & older than origin)
            """,
        )


    @mock.patch('git_machete.utils.run_cmd', mock_run_cmd)  # to hide git outputs in tests
    def test_add(self) -> None:
        """
        Verify behaviour of a 'git machete add' command.
        """
        (
            self.repo_sandbox.new_branch("master")
                .commit("master commit.")
                .new_branch("develop")
                .commit("develop commit.")
                .new_branch("feature")
                .commit("feature commit.")
                .check_out("develop")
                .commit("New commit on develop")
        )
        self.launch_command("discover", "-y")
        self.repo_sandbox.new_branch("bugfix/feature_fail")

        self.assert_command(['add', '-y', 'bugfix/feature_fail'], 'Adding `bugfix/feature_fail` onto the inferred upstream (parent) branch `develop`\n'
                                                                  'Added branch `bugfix/feature_fail` onto `develop`\n', strip_indentation=False)

        # test with --onto option
        self.repo_sandbox.new_branch("chore/remove_indentation")

        self.assert_command(['add', '--onto=feature'],
                            'Added branch `chore/remove_indentation` onto `feature`\n',
                            strip_indentation=False)

    @mock.patch('git_machete.client.MacheteClient.should_perform_interactive_slide_out', mock_should_perform_interactive_slide_out)
    @mock.patch('git_machete.client.MacheteClient.ask_if', mock_ask_if)
    @mock.patch('git_machete.utils.run_cmd', mock_run_cmd)
    def test_clean(self) -> None:
        (
            self.repo_sandbox.new_branch('master')
                .commit()
                .push()
                .new_branch('bar')
                .commit()
                .new_branch('bar2')
                .commit()
                .check_out("master")
                .new_branch('foo')
                .commit()
                .push()
                .new_branch('foo2')
                .commit()
                .check_out("master")
                .new_branch('moo')
                .commit()
                .new_branch('moo2')
                .commit()
        )
        self.launch_command('discover')
        (
            self.repo_sandbox
                .check_out("master")
                .new_branch('mars')
                .commit()
                .check_out("master")
        )
        self.launch_command('clean')

        expected_status_output = (
            """
            master *
            |
            o-bar (untracked)
            |
            o-foo
            |
            o-moo (untracked)
            """
        )
        self.assert_command(['status'], expected_status_output)

        with self.assertRaises(
                subprocess.CalledProcessError,
                msg="Verify that 'git checkout mars' raises an error when branch mars is no longer present in git."):
            self.repo_sandbox.check_out("mars")
