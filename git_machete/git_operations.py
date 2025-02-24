import os
import re
import shlex
import string
import sys
from pathlib import Path
from typing import (Any, Callable, Dict, Generator, Iterator, List, Match,
                    NamedTuple, Optional, Set, Tuple)

from git_machete import git_config_keys, utils
from git_machete.constants import (MAX_COUNT_FOR_INITIAL_LOG,
                                   GitFormatPatterns, SyncToRemoteStatuses)
from git_machete.exceptions import MacheteException
from git_machete.utils import (AnsiEscapeCodes, CommandResult, colored, debug,
                               fmt)

GITHUB_NEW_ISSUE_MESSAGE = 'Consider posting an issue at https://github.com/VirtusLab/git-machete/issues/new'


class AnyRevision(str):
    @staticmethod
    def of(value: str) -> "AnyRevision":
        if not value:
            raise TypeError(f'AnyRevision.of should not accept {value} as a param.\n' + GITHUB_NEW_ISSUE_MESSAGE)

        return AnyRevision(value)

    def full_name(self) -> "AnyRevision":
        return self


class AnyBranchName(AnyRevision):
    @staticmethod
    def of(value: str) -> "AnyBranchName":
        if not value:
            raise TypeError(f'AnyBranchName.of should not accept {value} as a param.\n' + GITHUB_NEW_ISSUE_MESSAGE)
        return AnyBranchName(value)

    def full_name(self) -> "AnyBranchName":
        return self


class LocalBranchShortName(AnyBranchName):
    @staticmethod
    def of(value: str) -> "LocalBranchShortName":
        if value.startswith('refs/heads/') or value.startswith('refs/remotes/'):
            raise TypeError(
                f'LocalBranchShortName cannot accept `refs/heads` or `refs/remotes`. Given value: {value}.\n' + GITHUB_NEW_ISSUE_MESSAGE)
        else:
            return LocalBranchShortName(value)

    def full_name(self) -> "LocalBranchFullName":
        return LocalBranchFullName.from_short_name(self)


class LocalBranchFullName(AnyBranchName):
    @staticmethod
    def of(value: str) -> "LocalBranchFullName":
        if value and value.startswith('refs/heads/'):
            return LocalBranchFullName(value)
        else:
            raise TypeError(
                f'LocalBranchFullName needs to have `refs/heads` prefix before branch name. Given value: {value}.\n' +
                GITHUB_NEW_ISSUE_MESSAGE)

    @staticmethod
    def from_short_name(value: LocalBranchShortName) -> "LocalBranchFullName":
        return LocalBranchFullName.of(f"refs/heads/{value}")

    def full_name(self) -> "LocalBranchFullName":
        return self

    def to_short_name(self) -> "LocalBranchShortName":
        return LocalBranchShortName.of(re.sub("^refs/heads/", "", self))


class RemoteBranchShortName(AnyBranchName):
    @staticmethod
    def of(value: str) -> "RemoteBranchShortName":
        if value and value.startswith('refs/heads/') or value.startswith('refs/remotes/'):
            raise TypeError(
                f'RemoteBranchShortName cannot accept `refs/heads` or `refs/remotes`. Given value: {value}.\n' + GITHUB_NEW_ISSUE_MESSAGE)
        else:
            return RemoteBranchShortName(value)

    def full_name(self) -> "RemoteBranchFullName":
        return RemoteBranchFullName.from_short_name(self)


class RemoteBranchFullName(AnyBranchName):
    @staticmethod
    def of(value: str) -> "RemoteBranchFullName":
        if value and value.startswith('refs/remotes/'):
            return RemoteBranchFullName(value)
        else:
            raise TypeError(
                f'RemoteBranchFullName needs to have `refs/remotes` prefix before branch name. Given value: {value}.\n' +
                GITHUB_NEW_ISSUE_MESSAGE)

    @staticmethod
    def is_valid(value: str) -> bool:
        return value is not None and value.startswith('refs/remotes/')

    @staticmethod
    def from_short_name(value: RemoteBranchShortName) -> "RemoteBranchFullName":
        return RemoteBranchFullName.of(f"refs/remotes/{value}")

    def full_name(self) -> "RemoteBranchFullName":
        return self

    def to_short_name(self) -> "RemoteBranchShortName":
        return RemoteBranchShortName.of(re.sub("^refs/remotes/", "", self))


class FullCommitHash(AnyRevision):
    @staticmethod
    def of(value: str) -> "FullCommitHash":
        if value and len(value) == 40:
            return FullCommitHash(value)
        else:
            raise TypeError(
                f'FullCommitHash requires length of 40. Given value: "{value}".\n' + GITHUB_NEW_ISSUE_MESSAGE)

    @staticmethod
    def is_valid(value: str) -> bool:
        return len(value) == 40 and all(c in string.hexdigits for c in value)

    def full_name(self) -> "FullCommitHash":
        return self


class ShortCommitHash(AnyRevision):
    @staticmethod
    def of(value: str) -> "ShortCommitHash":
        if value and len(value) >= 7:
            return ShortCommitHash(value)
        else:
            raise TypeError(
                f'ShortCommitHash requires length greater or equal to 7. Given value: "{value}".\n' +
                GITHUB_NEW_ISSUE_MESSAGE)

    def full_name(self) -> "ShortCommitHash":
        return self


class FullTreeHash(str):
    @staticmethod
    def of(value: str) -> Optional["FullTreeHash"]:
        if not value:
            raise TypeError(f'FullTreeHash.of should not accept {value} as a param.\n' + GITHUB_NEW_ISSUE_MESSAGE)
        return FullTreeHash(value)


class ForkPointOverrideData:
    def __init__(self, to_hash: FullCommitHash):
        self.to_hash: FullCommitHash = to_hash


class GitLogEntry(NamedTuple):
    hash: FullCommitHash
    short_hash: ShortCommitHash
    subject: str


class GitReflogEntry(NamedTuple):
    hash: FullCommitHash
    reflog_subject: str


class BranchPair(NamedTuple):
    local_branch: LocalBranchShortName
    local_or_remote_branch: AnyBranchName


HEAD = AnyRevision.of("HEAD")


class GitContext:

    def __init__(self) -> None:
        self._git_version: Optional[Tuple[int, ...]] = None
        self._root_dir: Optional[str] = None
        self._main_git_dir: Optional[str] = None
        self._worktree_git_dir: Optional[str] = None
        self.__fetch_done_for: Set[str] = set()
        self.__config_cached: Optional[Dict[str, str]] = None
        self.__remotes_cached: Optional[List[str]] = None
        self.__counterparts_for_fetching_cached: Optional[
            Dict[LocalBranchShortName, Optional[RemoteBranchShortName]]] = None  # TODO (#110): default dict with None
        self.__short_commit_hash_by_revision_cached: Dict[AnyRevision, Optional[ShortCommitHash]] = {}
        self.__tree_hash_by_commit_hash_cached: Optional[
            Dict[FullCommitHash, Optional[FullTreeHash]]] = None  # TODO (#110): default dict with None
        self.__commit_hash_by_revision_cached: Optional[
            Dict[AnyRevision, Optional[FullCommitHash]]] = None  # TODO (#110): default dict with None
        self.__committer_unix_timestamp_by_revision_cached: Optional[Dict[AnyRevision, int]] = None  # TODO (#110): default dict with 0
        self.__local_branches_cached: Optional[List[LocalBranchShortName]] = None
        self.__remote_branches_cached: Optional[List[RemoteBranchShortName]] = None
        self.__initial_log_hashes_cached: Dict[FullCommitHash, List[FullCommitHash]] = {}
        self.__remaining_log_hashes_cached: Dict[FullCommitHash, List[FullCommitHash]] = {}
        self.__reflogs_cached: Optional[Dict[AnyBranchName, List[GitReflogEntry]]] = None
        self.__merge_base_cached: Dict[Tuple[FullCommitHash, FullCommitHash], Optional[FullCommitHash]] = {}
        self.__is_equivalent_tree_reachable_cached: Dict[Tuple[FullCommitHash, FullCommitHash], bool] = {}

    @staticmethod
    def _run_git(git_cmd: str, *args: str, **kwargs: Any) -> int:
        kwargs_ = kwargs.copy()
        allow_non_zero = kwargs_.pop("allow_non_zero", False)
        exit_code = utils.run_cmd("git", git_cmd, *args, **kwargs_)
        if not allow_non_zero and exit_code != 0:
            raise MacheteException(f"`{utils.get_cmd_shell_repr('git', git_cmd, *args, env=kwargs_.get('env'))}` returned {exit_code}")
        return exit_code

    @staticmethod
    def _popen_git(git_cmd: str, *args: str, **kwargs: Any) -> CommandResult:
        kwargs_ = kwargs.copy()
        allow_non_zero = kwargs_.pop("allow_non_zero", False)
        exit_code, stdout, stderr = utils.popen_cmd("git", git_cmd, *args, **kwargs_)
        if not allow_non_zero and exit_code != 0:
            exit_code_msg: str = fmt(f"`{utils.get_cmd_shell_repr('git', git_cmd, *args, env=kwargs_.get('env'))}` returned {exit_code}\n")
            stdout_msg: str = f"\n{utils.bold('stdout')}:\n{utils.dim(stdout)}" if stdout else ""
            stderr_msg: str = f"\n{utils.bold('stderr')}:\n{utils.dim(stderr)}" if stderr else ""
            # Not applying the formatter to avoid transforming whatever characters might be in the output of the command.
            raise MacheteException(exit_code_msg + stdout_msg + stderr_msg, apply_fmt=False)
        return CommandResult(stdout, stderr, exit_code)

    def get_default_editor_with_args(self) -> List[str]:
        # Based on the git's own algorithm for identifying the editor.
        # '$GIT_MACHETE_EDITOR', 'editor' (to please Debian-based systems) and 'nano' have been added.
        git_machete_editor_var = "GIT_MACHETE_EDITOR"
        proposed_editor_funs: List[Tuple[str, Callable[[], Optional[str]]]] = [
            ("$" + git_machete_editor_var, lambda: os.environ.get(git_machete_editor_var)),
            ("$GIT_EDITOR", lambda: os.environ.get("GIT_EDITOR")),
            ("git config core.editor", lambda: self.get_config_attr_or_none("core.editor")),
            ("$VISUAL", lambda: os.environ.get("VISUAL")),
            ("$EDITOR", lambda: os.environ.get("EDITOR")),
            ("editor", lambda: "editor"),
            ("nano", lambda: "nano"),
            ("vi", lambda: "vi"),
        ]

        for name, fun in proposed_editor_funs:
            editor = fun()
            if not editor:
                debug(f"'{name}' is undefined")
            else:
                editor_parsed = shlex.split(editor)
                if not editor_parsed:
                    debug(f"'{name}' shlexes into an empty list")
                    continue
                editor_command = editor_parsed[0]
                editor_repr = "'" + name + "'" + ((' (' + editor + ')') if editor_command != name else '')

                if not utils.find_executable(editor_command):
                    debug(f"'{editor_command}' executable ('{name}') not found")
                    if name == "$" + git_machete_editor_var:
                        # In this specific case, when GIT_MACHETE_EDITOR is defined but doesn't point to a valid executable,
                        # it's more reasonable/less confusing to raise an error and exit without opening anything.
                        raise MacheteException(f"<b>{editor_repr}</b> is not available")
                else:
                    debug(f"'{editor_command}' executable ('{name}') found")
                    if name != "$" + git_machete_editor_var and self.get_config_attr_or_none('advice.macheteEditorSelection') != 'false':
                        sample_alternative = 'nano' if editor_command.startswith('vi') else 'vi'
                        print(fmt(f"Opening <b>{editor_repr}</b>.\n",
                                  f"To override this choice, use <b>{git_machete_editor_var}</b> env var, e.g. `export "
                                  f"{git_machete_editor_var}={sample_alternative}`.\n\n",
                                  "See `git machete help edit` and `git machete edit --debug` for more details.\n\n"
                                  "Use `git config --global advice.macheteEditorSelection false` to suppress this message."),
                              file=sys.stderr)
                    return editor_parsed

        # This case is extremely unlikely on a modern Unix-like system.
        return []

    def get_git_version(self) -> Tuple[int, ...]:
        if not self._git_version:
            # We need to cut out the x.y.z part and not just take the result of 'git version' as is,
            # because the version string in certain distributions of git (esp. on OS X) has an extra suffix,
            # which is irrelevant for our purpose (checking whether certain git CLI features are available/bugs are fixed).
            raw = re.search(r"\d+.\d+.\d+", self._popen_git("version").stdout)
            if not raw:  # unlikely, never observed so far; mostly to satisfy mypy
                return 0, 0, 0
            self._git_version = tuple(map(int, raw.group(0).split(".")))
        return self._git_version

    def get_root_dir(self) -> str:
        if not self._root_dir:
            try:
                self._root_dir = self._popen_git("rev-parse", "--show-toplevel").stdout.strip()
            except MacheteException:
                raise MacheteException("Not a git repository")
        return self._root_dir

    def __get_worktree_git_dir(self) -> str:
        if not self._worktree_git_dir:
            try:
                self._worktree_git_dir = self._popen_git("rev-parse", "--git-dir").stdout.strip()
            except MacheteException:
                raise MacheteException("Not a git repository")
        return self._worktree_git_dir

    def __get_main_git_dir(self) -> str:
        if not self._main_git_dir:
            try:
                git_dir: str = self._popen_git("rev-parse", "--git-dir").stdout.strip()
                git_dir_parts = Path(git_dir).parts
                if len(git_dir_parts) >= 3 and git_dir_parts[-3] == '.git' and git_dir_parts[-2] == 'worktrees':
                    self._main_git_dir = os.path.join(*git_dir_parts[:-2])
                    debug(f'git dir pointing to {git_dir} - we are in a worktree; '
                          f'using {self._main_git_dir} as the effective git dir instead')
                else:
                    self._main_git_dir = git_dir
            except MacheteException:
                raise MacheteException("Not a git repository")
        return self._main_git_dir

    def get_worktree_git_subpath(self, *fragments: str) -> str:
        return os.path.join(self.__get_worktree_git_dir(), *fragments)

    def get_main_git_subpath(self, *fragments: str) -> str:
        return os.path.join(self.__get_main_git_dir(), *fragments)

    def get_git_machete_definition_file_path(self) -> str:
        use_top_level_machete_file = self.get_boolean_config_attr(key=git_config_keys.WORKTREE_USE_TOP_LEVEL_MACHETE_FILE,
                                                                  default_value=True)
        return os.path.join(self.__get_main_git_dir() if use_top_level_machete_file else self.__get_worktree_git_dir(), 'machete')

    def get_git_timespec_parsed_to_unix_timestamp(self, date: str) -> int:
        try:
            return int(self._popen_git("rev-parse", "--since=" + date).stdout.replace("--max-age=", "").strip())
        except (MacheteException, ValueError):
            raise MacheteException(f"Cannot parse timespec: `{date}`")

    def __ensure_config_loaded(self) -> None:
        if self.__config_cached is None:
            self.__config_cached = {}
            for config_line in utils.get_non_empty_lines(self._popen_git("config", "--list").stdout):
                k_v = config_line.split("=", 1)
                if len(k_v) == 2:
                    k, v = k_v
                    self.__config_cached[k.lower()] = v

    def get_config_attr_or_none(self, key: str) -> Optional[str]:
        self.__ensure_config_loaded()
        assert self.__config_cached is not None
        return self.__config_cached.get(key.lower())

    def get_boolean_config_attr(self, key: str, default_value: bool) -> bool:
        value = self.get_boolean_config_attr_or_none(key)
        return value if value is not None else default_value

    def get_boolean_config_attr_or_none(self, key: str) -> Optional[bool]:
        self.__ensure_config_loaded()
        assert self.__config_cached is not None
        if self.__config_cached.get(key.lower()) is not None:
            return self.__config_cached.get(key.lower()) == 'true'
        return None

    def set_config_attr(self, key: str, value: str) -> None:
        self._run_git("config", "--", key, value)
        self.__ensure_config_loaded()
        assert self.__config_cached is not None
        self.__config_cached[key.lower()] = value

    def unset_config_attr(self, key: str) -> None:
        self.__ensure_config_loaded()
        assert self.__config_cached is not None
        if self.get_config_attr_or_none(key):
            self._run_git("config", "--unset", key)
            del self.__config_cached[key.lower()]

    def add_remote(self, name: str, url: str) -> None:
        self._run_git('remote', 'add', name, url)
        self.flush_caches()

    def get_remotes(self) -> List[str]:
        if self.__remotes_cached is None:
            self.__remotes_cached = utils.get_non_empty_lines(self._popen_git("remote").stdout)
        return self.__remotes_cached

    def get_url_of_remote(self, remote: str) -> Optional[str]:
        self.__ensure_config_loaded()
        url = self.get_config_attr_or_none(f"remote.{remote}.url")  # 'git remote get-url' method has only been added in git v2.5.1
        return url.strip() if url else None

    def fetch_remote(self, remote: str) -> None:
        if remote not in self.__fetch_done_for:
            self._run_git("fetch", remote, "--prune")  # --prune added to remove remote branches that are already deleted from remote
            self.__fetch_done_for.add(remote)
            self.flush_caches()

    def fetch_ref(self, remote: str, ref: str) -> None:
        self._run_git("fetch", remote, ref)
        self.flush_caches()

    def set_upstream_to(self, remote_branch: RemoteBranchShortName) -> None:
        self._run_git("branch", "--set-upstream-to", remote_branch)
        self.flush_caches()

    def reset_keep(self, to_revision: AnyRevision) -> None:
        try:
            self._run_git("reset", "--keep", to_revision)
        except MacheteException:
            raise MacheteException(
                f"Cannot perform `git reset --keep {to_revision}`. This is most likely caused by local uncommitted changes.")

    def push(self, remote: str, branch: LocalBranchShortName, force_with_lease: bool = False) -> None:
        if not force_with_lease:
            opt_force = []
        elif self.get_git_version() >= (1, 8, 5):  # earliest version of git to support 'push --force-with-lease'
            opt_force = ["--force-with-lease"]
        else:
            opt_force = ["--force"]
        args = [remote, branch]
        self._run_git("push", "--set-upstream", *(opt_force + args))
        self.flush_caches()

    def pull_ff_only(self, remote: str, remote_branch: RemoteBranchShortName) -> None:
        self.fetch_remote(remote)
        self._run_git("merge", "--ff-only", remote_branch)
        # There's apparently no way to set remote automatically when doing 'git pull' (as opposed to 'git push'),
        # so a separate 'git branch --set-upstream-to' is needed.
        self.set_upstream_to(remote_branch)
        self.flush_caches()

    def __find_short_commit_hash_by_revision(self, revision: AnyRevision) -> ShortCommitHash:
        return ShortCommitHash.of(self._popen_git("rev-parse", "--short", revision + "^{commit}").stdout.rstrip())  # noqa: FS003

    def get_short_commit_hash_by_revision_or_none(self, revision: AnyRevision) -> Optional[ShortCommitHash]:
        if revision not in self.__short_commit_hash_by_revision_cached:
            try:
                self.__short_commit_hash_by_revision_cached[revision] = self.__find_short_commit_hash_by_revision(revision)
            except MacheteException:
                self.__short_commit_hash_by_revision_cached[revision] = None
        return self.__short_commit_hash_by_revision_cached[revision]

    def __find_commit_hash_by_revision(self, revision: AnyRevision) -> Optional[FullCommitHash]:
        # Without ^{commit}, 'git rev-parse --verify' will not only accept references to other kinds of objects (like trees and blobs),
        # but just echo the argument (and exit successfully) even if the argument doesn't match anything in the object store.
        try:
            return FullCommitHash.of(self._popen_git("rev-parse", "--verify", "--quiet", revision + "^{commit}").stdout.rstrip())  # noqa: FS003, E501
        except MacheteException:
            return None

    def get_commit_hash_by_revision(self, revision: AnyRevision) -> Optional[FullCommitHash]:
        if self.is_full_hash(revision.full_name()):
            return FullCommitHash.of(revision)
        if self.__commit_hash_by_revision_cached is None:
            self.__load_branches()
        assert self.__commit_hash_by_revision_cached is not None
        if revision not in self.__commit_hash_by_revision_cached:
            self.__commit_hash_by_revision_cached[revision] = self.__find_commit_hash_by_revision(revision)
        return self.__commit_hash_by_revision_cached[revision]

    def __find_tree_hash_by_revision(self, revision: AnyRevision) -> Optional[FullTreeHash]:
        try:
            return FullTreeHash.of(self._popen_git("rev-parse", "--verify", "--quiet", revision + "^{tree}").stdout.rstrip())  # noqa: FS003
        except MacheteException:
            return None

    def get_tree_hash_by_commit_hash(self, commit_hash: FullCommitHash) -> Optional[FullTreeHash]:
        if self.__tree_hash_by_commit_hash_cached is None:
            self.__load_branches()
        assert self.__tree_hash_by_commit_hash_cached is not None
        if commit_hash not in self.__tree_hash_by_commit_hash_cached:
            self.__tree_hash_by_commit_hash_cached[commit_hash] = self.__find_tree_hash_by_revision(commit_hash)
        return self.__tree_hash_by_commit_hash_cached[commit_hash]

    @staticmethod
    def is_full_hash(revision: AnyRevision) -> Optional[Match[str]]:
        return re.match("^[0-9a-f]{40}$", revision)  # noqa: FS003

    def is_commit_present_in_repository(self, revision: AnyRevision) -> bool:
        return self._popen_git("rev-parse", "--verify", "--quiet", revision + "^{commit}", allow_non_zero=True).exit_code == 0  # noqa: FS003, E501

    def get_committer_unix_timestamp_by_revision(self, revision: AnyBranchName) -> int:
        if self.__committer_unix_timestamp_by_revision_cached is None:
            self.__load_branches()
        assert self.__committer_unix_timestamp_by_revision_cached is not None
        return self.__committer_unix_timestamp_by_revision_cached.get(revision.full_name(), 0)

    def __get_remotes_containing_branch(self, branch: LocalBranchShortName, remotes: Optional[List[str]] = None) -> List[str]:
        remotes = remotes if remotes else self.get_remotes()
        remote_branches = self.get_remote_branches()
        return [remote for remote in remotes if f'{remote}/{branch}' in remote_branches]

    def get_inferred_remote_for_fetching_of_branch(self,
                                                   branch: LocalBranchShortName,
                                                   remotes: Optional[List[str]] = None
                                                   ) -> Optional[str]:
        remotes_containing_branch: List[str] = self.__get_remotes_containing_branch(branch=branch, remotes=remotes)
        if len(remotes_containing_branch) > 1 or len(remotes_containing_branch) == 0:
            debug(f'Can\'t infer remote for fetching of branch.\n'
                  f'There are {len(remotes_containing_branch)} remotes: {", ".join(remotes_containing_branch)} '
                  f'containing {branch} branch.')
            return None
        else:
            return remotes_containing_branch[0]

    def get_strict_remote_for_fetching_of_branch(self, branch: LocalBranchShortName) -> Optional[str]:
        remote = self.get_config_attr_or_none(f"branch.{branch}.remote")
        return remote.rstrip() if remote else None

    def get_combined_remote_for_fetching_of_branch(self,
                                                   branch: LocalBranchShortName,
                                                   remotes: Optional[List[str]] = None
                                                   ) -> Optional[str]:
        # Since many people don't use '--set-upstream' flag of 'push', we try to infer the remote instead if the tracking data is missing.
        return self.get_strict_remote_for_fetching_of_branch(branch) or self.get_inferred_remote_for_fetching_of_branch(branch, remotes)

    def __get_inferred_counterpart_for_fetching_of_branch(self, branch: LocalBranchShortName) -> Optional[RemoteBranchShortName]:
        remotes_containing_branch: List[str] = self.__get_remotes_containing_branch(branch)
        if len(remotes_containing_branch) > 1 or len(remotes_containing_branch) == 0:
            debug(f'Can\'t infer local branch\'s remote counterpart for fetching of branch.\n'
                  f'There are {len(remotes_containing_branch)} remotes: {", ".join(remotes_containing_branch)} '
                  f'containing branch {branch}.')
            return None
        else:
            return RemoteBranchShortName.of(f"{remotes_containing_branch[0]}/{branch}")

    def get_strict_counterpart_for_fetching_of_branch(self, branch: LocalBranchShortName) -> Optional[RemoteBranchShortName]:
        if self.__counterparts_for_fetching_cached is None:
            self.__load_branches()
        assert self.__counterparts_for_fetching_cached is not None
        return self.__counterparts_for_fetching_cached.get(branch)

    def get_combined_counterpart_for_fetching_of_branch(self, branch: LocalBranchShortName) -> Optional[RemoteBranchShortName]:
        # Since many people don't use '--set-upstream' flag of 'push' or 'branch',
        # we try to infer the remote if the tracking data is missing.
        return self.get_strict_counterpart_for_fetching_of_branch(branch) or self.__get_inferred_counterpart_for_fetching_of_branch(branch)

    # Note that rebase/cherry-pick/merge/revert all happen on per-worktree basis,
    # so we need to check .git/worktrees/<worktree>/<file> rather than .git/<file>

    def is_am_in_progress(self) -> bool:
        # As of git 2.24.1, this is how 'cmd_rebase()' in builtin/rebase.c checks whether am is in progress.
        return os.path.isfile(self.get_worktree_git_subpath("rebase-apply", "applying"))

    def is_cherry_pick_in_progress(self) -> bool:
        return os.path.isfile(self.get_worktree_git_subpath("CHERRY_PICK_HEAD"))

    def is_merge_in_progress(self) -> bool:
        return os.path.isfile(self.get_worktree_git_subpath("MERGE_HEAD"))

    def is_revert_in_progress(self) -> bool:
        return os.path.isfile(self.get_worktree_git_subpath("REVERT_HEAD"))

    def checkout(self, branch: LocalBranchShortName) -> None:
        self._run_git("checkout", "--quiet", branch, "--")
        self.flush_caches()

    def get_local_branches(self) -> List[LocalBranchShortName]:
        if self.__local_branches_cached is None:
            self.__load_branches()
        assert self.__local_branches_cached is not None
        return self.__local_branches_cached

    def get_remote_branches(self) -> List[RemoteBranchShortName]:
        if self.__remote_branches_cached is None:
            self.__load_branches()
        assert self.__remote_branches_cached is not None
        return self.__remote_branches_cached

    def __load_branches(self) -> None:
        self.__commit_hash_by_revision_cached = {}
        self.__committer_unix_timestamp_by_revision_cached = {}
        self.__counterparts_for_fetching_cached = {}
        self.__local_branches_cached = []
        self.__remote_branches_cached = []
        self.__tree_hash_by_commit_hash_cached = {}

        # Using 'committerdate:raw' instead of 'committerdate:unix' since the latter isn't supported by some older versions of git.
        raw_remote = utils.get_non_empty_lines(
            self._popen_git("for-each-ref", "--format=%(refname)\t%(objectname)\t%(tree)\t%(committerdate:raw)", "refs/remotes").stdout)
        for line in raw_remote:
            values = line.split("\t")
            if len(values) != 4:
                continue  # invalid, shouldn't happen
            branch, commit_hash, tree_hash, committer_unix_timestamp_and_time_zone = values
            b_stripped_remote = RemoteBranchFullName.of(branch).to_short_name()
            self.__remote_branches_cached += [b_stripped_remote]
            self.__commit_hash_by_revision_cached[RemoteBranchFullName.of(branch)] = FullCommitHash.of(commit_hash)
            self.__tree_hash_by_commit_hash_cached[FullCommitHash.of(commit_hash)] = FullTreeHash.of(tree_hash)
            self.__committer_unix_timestamp_by_revision_cached[RemoteBranchFullName.of(branch)] = int(
                committer_unix_timestamp_and_time_zone.split(' ')[0])

        raw_local = utils.get_non_empty_lines(
            self._popen_git("for-each-ref", "--format=%(refname)\t%(objectname)\t%(tree)\t%(committerdate:raw)\t%(upstream)",
                            "refs/heads").stdout)

        for line in raw_local:
            values = line.split("\t")
            if len(values) != 5:
                continue  # invalid, shouldn't happen
            branch, commit_hash, tree_hash, committer_unix_timestamp_and_time_zone, fetch_counterpart = values
            b_stripped_local = LocalBranchFullName.of(branch).to_short_name()
            # fetch_counterpart might be empty, or might even point to a local branch
            # (in case `branch.BRANCH.remote` config is set to `.`).
            if RemoteBranchFullName.is_valid(fetch_counterpart):
                fetch_counterpart_stripped = RemoteBranchFullName.of(fetch_counterpart).to_short_name()
            else:
                fetch_counterpart_stripped = None
            self.__local_branches_cached += [b_stripped_local]
            self.__commit_hash_by_revision_cached[LocalBranchFullName.of(branch)] = FullCommitHash.of(commit_hash)
            self.__tree_hash_by_commit_hash_cached[FullCommitHash.of(commit_hash)] = FullTreeHash.of(tree_hash)
            self.__committer_unix_timestamp_by_revision_cached[LocalBranchFullName.of(branch)] = int(
                committer_unix_timestamp_and_time_zone.split(' ')[0])
            if fetch_counterpart_stripped in self.__remote_branches_cached:
                self.__counterparts_for_fetching_cached[b_stripped_local] = fetch_counterpart_stripped

    def __get_log_hashes(self, revision: AnyRevision, max_count: Optional[int]) -> List[FullCommitHash]:
        opts = ([f"--max-count={str(max_count)}"] if max_count else []) + ["--format=%H", revision.full_name()]
        return list(map(FullCommitHash.of, utils.get_non_empty_lines(self._popen_git("log", *opts).stdout)))

    # Since getting the full history of a branch can be an expensive operation for large repositories
    # (compared to all other underlying git operations), there's a simple optimization in place:
    # we first fetch only a couple of first commits in the history, and only fetch the rest if needed.
    def spoonfeed_log_hashes(self, branch_full_hash: FullCommitHash) -> Generator[FullCommitHash, None, None]:
        if branch_full_hash not in self.__initial_log_hashes_cached:
            self.__initial_log_hashes_cached[branch_full_hash] = self.__get_log_hashes(branch_full_hash,
                                                                                       max_count=MAX_COUNT_FOR_INITIAL_LOG)
        for hash in self.__initial_log_hashes_cached[branch_full_hash]:
            yield FullCommitHash.of(hash)

        if branch_full_hash not in self.__remaining_log_hashes_cached:
            self.__remaining_log_hashes_cached[branch_full_hash] = self.__get_log_hashes(branch_full_hash,
                                                                                         max_count=None)[MAX_COUNT_FOR_INITIAL_LOG:]
        for hash in self.__remaining_log_hashes_cached[branch_full_hash]:
            yield FullCommitHash.of(hash)

    def __load_all_reflogs(self) -> None:
        # %gd - reflog selector (refname@{num})
        # %H - full hash
        # %gs - reflog subject
        local_branches: List[str] = [branch.full_name() for branch in self.get_local_branches()]  # str to match _popen_git() input type

        def get_counterpart_branches() -> Generator[str, None, None]:
            for branch in self.get_local_branches():
                counterpart = self.get_combined_counterpart_for_fetching_of_branch(branch)
                if counterpart:
                    yield counterpart.full_name()
        counterpart_branches: List[str] = list(get_counterpart_branches())

        all_branches: List[str] = local_branches + counterpart_branches

        # The trailing '--' is necessary to avoid ambiguity in case there is a file called just exactly like one of the branches.
        entries = utils.get_non_empty_lines(self._popen_git("reflog", "show", "--format=%gD\t%H\t%gs", *(all_branches + ["--"])).stdout)
        self.__reflogs_cached = {}
        for entry in entries:
            values = entry.split("\t")
            if len(values) != 3:  # invalid, shouldn't happen
                continue
            selector, hash, subject = values
            branch_and_pos = selector.split("@")
            if len(branch_and_pos) != 2:  # invalid, shouldn't happen
                continue
            branch, pos = branch_and_pos
            any_branch_name = AnyBranchName.of(branch)
            if any_branch_name not in self.__reflogs_cached:
                self.__reflogs_cached[any_branch_name] = []
            self.__reflogs_cached[any_branch_name] += [GitReflogEntry(hash=FullCommitHash.of(hash), reflog_subject=subject)]

    def get_reflog(self, branch: AnyBranchName) -> List[GitReflogEntry]:
        # git version 2.14.2 fixed a bug that caused fetching reflog of more than
        # one branch at the same time unreliable in certain cases
        if self.get_git_version() >= (2, 14, 2):
            if self.__reflogs_cached is None:
                self.__load_all_reflogs()
            assert self.__reflogs_cached is not None
            return self.__reflogs_cached.get(branch, [])
        else:
            if self.__reflogs_cached is None:
                self.__reflogs_cached = {}
            if branch not in self.__reflogs_cached:
                # %H - full hash
                # %gs - reflog subject
                self.__reflogs_cached[branch] = list(map(lambda x: GitReflogEntry(hash=FullCommitHash(x[0]), reflog_subject=x[1]),
                                                         [entry.split(":", 1) for entry in utils.get_non_empty_lines(
                                                             # The trailing '--' is necessary to avoid ambiguity in case there is a file
                                                             # called just exactly like the branch 'branch'.
                                                             self._popen_git("reflog", "show", "--format=%H:%gs", branch, "--").stdout)]
                                                         ))
            return self.__reflogs_cached[branch]

    def create_branch(self, branch: LocalBranchShortName, out_of_revision: AnyRevision, switch_head: bool) -> None:
        self._run_git("branch", branch, out_of_revision)
        if switch_head:
            self._run_git("checkout", branch)
        self.flush_caches()  # the repository state has changed because of a successful branch creation,
        # let's defensively flush all the caches

    def flush_caches(self) -> None:
        self.__config_cached = None
        self.__remotes_cached = None
        self.__counterparts_for_fetching_cached = None
        self.__short_commit_hash_by_revision_cached = {}
        self.__commit_hash_by_revision_cached = None
        self.__committer_unix_timestamp_by_revision_cached = None
        self.__local_branches_cached = None
        self.__remote_branches_cached = None
        self.__reflogs_cached = None

    def get_revision_repr(self, revision: AnyRevision) -> str:
        short_hash = self.get_short_commit_hash_by_revision_or_none(revision)
        if not short_hash or self.is_full_hash(revision.full_name()) or revision == short_hash:
            return f"commit <b>{revision}</b>"
        else:
            return f"<b>{revision}</b> (commit <b>{short_hash}</b>)"

    # Note: while rebase is ongoing, the repository is always in a detached HEAD state,
    # so we need to extract the name of the currently rebased branch from the rebase-specific internals
    # rather than rely on 'git symbolic-ref HEAD' (i.e. the contents of .git/HEAD).
    def get_currently_rebased_branch_or_none(self) -> Optional[LocalBranchShortName]:  # utils/private
        # https://stackoverflow.com/questions/3921409

        head_name_file = None

        # .git/rebase-merge directory exists during cherry-pick-powered rebases,
        # e.g. all interactive ones and the ones where '--strategy=' or '--keep-empty' option has been passed
        rebase_merge_head_name_file = self.get_worktree_git_subpath("rebase-merge", "head-name")
        if os.path.isfile(rebase_merge_head_name_file):
            head_name_file = rebase_merge_head_name_file

        # .git/rebase-apply directory exists during the remaining, i.e. am-powered rebases, but also during am sessions.
        rebase_apply_head_name_file = self.get_worktree_git_subpath("rebase-apply", "head-name")
        # Most likely .git/rebase-apply/head-name can't exist during am sessions, but it's better to be safe.
        if not self.is_am_in_progress() and os.path.isfile(rebase_apply_head_name_file):
            head_name_file = rebase_apply_head_name_file

        if not head_name_file:
            return None
        with open(head_name_file) as f:
            raw = f.read().strip()
            return LocalBranchFullName.of(raw).to_short_name()

    def get_currently_checked_out_branch_or_none(self) -> Optional[LocalBranchShortName]:
        try:
            raw = self._popen_git("symbolic-ref", "--quiet", "HEAD").stdout.strip()
            return LocalBranchFullName.of(raw).to_short_name()
        except MacheteException:
            return None

    def expect_no_operation_in_progress(self) -> None:
        remote_branch = self.get_currently_rebased_branch_or_none()
        if remote_branch:
            raise MacheteException(
                f"Rebase of {utils.bold(remote_branch)} in progress. "
                f"Conclude the rebase first with `git rebase --continue` or `git rebase --abort`.")
        if self.is_am_in_progress():
            raise MacheteException(
                "`git am` session in progress. Conclude `git am` first with `git am --continue` or `git am --abort`.")
        if self.is_cherry_pick_in_progress():
            raise MacheteException(
                "Cherry pick in progress. Conclude the cherry pick first with `git cherry-pick --continue` or `git cherry-pick --abort`.")
        if self.is_merge_in_progress():
            raise MacheteException(
                "Merge in progress. Conclude the merge first with `git merge --continue` or `git merge --abort`.")
        if self.is_revert_in_progress():
            raise MacheteException(
                "Revert in progress. Conclude the revert first with `git revert --continue` or `git revert --abort`.")

    def get_current_branch_or_none(self) -> Optional[LocalBranchShortName]:
        return self.get_currently_checked_out_branch_or_none() or self.get_currently_rebased_branch_or_none()

    def get_current_branch(self) -> LocalBranchShortName:
        result = self.get_current_branch_or_none()
        if not result:
            raise MacheteException("Not currently on any branch")
        return result

    def __get_merge_base_for_commit_hashes(self, hash1: FullCommitHash, hash2: FullCommitHash) -> Optional[FullCommitHash]:
        # This if statement is not changing the outcome of the later return, but
        # it enhances the efficiency of the script. If both hashes are the same,
        # there is no point running git merge-base.
        if hash1 == hash2:
            return hash1
        if hash1 > hash2:
            hash1, hash2 = hash2, hash1
        if not (hash1, hash2) in self.__merge_base_cached:
            # Note that we don't pass '--all' flag to 'merge-base', so we'll get only one merge-base
            # even if there is more than one (in the rare case of criss-cross histories).
            # This is still okay from the perspective of is-ancestor checks that are our sole use of merge-base:
            # * if any of hash1, hash2 is an ancestor of another,
            #   then there is exactly one merge-base - the ancestor,
            # * if neither of hash1, hash2 is an ancestor of another,
            #   then none of the (possibly more than one) merge-bases is equal to either of hash1/hash2 anyway.
            # In the rare case when hash1, hash2 have no common commits, the flag: allow_non_zero=True
            # (allows, non zero exit code to be returned by git merge-base command, without raising an exception)
            # is used and the __get_merge_base function returns None.
            merge_base = self._popen_git("merge-base", hash1, hash2, allow_non_zero=True).stdout.strip()
            self.__merge_base_cached[hash1, hash2] = FullCommitHash.of(merge_base) if merge_base else None
        return self.__merge_base_cached[hash1, hash2]

    # Note: the 'git rev-parse --verify' validation is not performed in case for either of earlier/later
    # if the corresponding prefix is empty AND the revision is a 40 hex digit hash.
    def is_ancestor_or_equal(
            self,
            earlier_revision: AnyRevision,
            later_revision: AnyRevision,
    ) -> bool:
        earlier_hash = self.get_commit_hash_by_revision(earlier_revision)
        later_hash = self.get_commit_hash_by_revision(later_revision)
        if not earlier_hash or not later_hash:
            return False
        return self.__get_merge_base_for_commit_hashes(earlier_hash, later_hash) == earlier_hash

    def get_merge_base(
            self,
            earlier_revision: AnyRevision,
            later_revision: AnyRevision,
    ) -> Optional[FullCommitHash]:
        earlier_hash = self.get_commit_hash_by_revision(earlier_revision)
        later_hash = self.get_commit_hash_by_revision(later_revision)
        if not earlier_hash or not later_hash:
            return None
        return self.__get_merge_base_for_commit_hashes(earlier_hash, later_hash)

    # Determine if reachable_from, or any ancestors of reachable_from that are NOT ancestors of equivalent_to,
    # contain a tree with identical contents to equivalent_to, indicating that
    # reachable_from contains a rebase or squash merge of equivalent_to.
    def is_equivalent_tree_reachable(
            self,
            equivalent_to: AnyRevision,
            reachable_from: AnyRevision,
    ) -> bool:
        equivalent_to_commit_hash = self.get_commit_hash_by_revision(equivalent_to)
        reachable_from_commit_hash = self.get_commit_hash_by_revision(reachable_from)
        if not equivalent_to_commit_hash or not reachable_from_commit_hash:
            return False

        if equivalent_to_commit_hash == reachable_from_commit_hash:
            return True

        if (equivalent_to_commit_hash, reachable_from_commit_hash) in self.__is_equivalent_tree_reachable_cached:
            return self.__is_equivalent_tree_reachable_cached[equivalent_to_commit_hash, reachable_from_commit_hash]

        earlier_tree_hash = self.get_tree_hash_by_commit_hash(equivalent_to_commit_hash)

        # `git log ^equivalent_to_commit_hash reachable_from_commit_hash`
        # shows all commits reachable from reachable_from_commit_hash but NOT from equivalent_to_commit_hash
        intermediate_tree_hashes = utils.get_non_empty_lines(
            self._popen_git(
                "log",
                "--format=%T",  # full commit's tree hash
                "^" + equivalent_to_commit_hash,
                reachable_from_commit_hash
            ).stdout
        )

        result = earlier_tree_hash in intermediate_tree_hashes
        debug(f"result = {result}")
        self.__is_equivalent_tree_reachable_cached[equivalent_to_commit_hash, reachable_from_commit_hash] = result
        return result

    def get_sole_remote_branch(self, branch: LocalBranchShortName) -> Optional[RemoteBranchShortName]:
        def matches(remote_branch: RemoteBranchShortName) -> bool:
            # Note that this matcher is defensively too inclusive:
            # if there is both origin/foo and origin/feature/foo,
            # then both are matched for 'foo';
            # this is to reduce risk wrt. which '/'-separated fragments belong to remote and which to branch name.
            # FIXME (#116): this is still likely to deliver incorrect results in rare corner cases with compound remote names.
            return remote_branch.endswith(f"/{branch}")

        matching_remote_branches = list(filter(matches, self.get_remote_branches()))
        return matching_remote_branches[0] if len(matching_remote_branches) == 1 else None

    def get_merged_local_branches(self) -> List[LocalBranchShortName]:
        if self.get_git_version() >= (2, 7, 6):  # earliest version of git to support 'for-each-ref --merged'
            return list(
                map(lambda branch: LocalBranchFullName.of(branch).to_short_name(),
                    utils.get_non_empty_lines(
                        self._popen_git("for-each-ref", "--format=%(refname)", "--merged", "HEAD", "refs/heads").stdout)))
        else:
            return list(
                filter(lambda branch: self.is_ancestor_or_equal(branch, AnyRevision.of('HEAD')),
                       map(lambda branch: LocalBranchFullName.of(branch).to_short_name(),
                           utils.get_non_empty_lines(
                               self._popen_git("for-each-ref", "--format=%(refname)", "refs/heads").stdout))))

    def get_hook_path(self, hook_name: str) -> str:
        hook_dir: str = self.get_config_attr_or_none("core.hooksPath") or self.get_main_git_subpath("hooks")
        return os.path.join(hook_dir, hook_name)

    def check_hook_executable(self, hook_path: str) -> bool:
        if not os.path.isfile(hook_path):
            return False
        elif not utils.is_executable(hook_path):
            advice_ignored_hook = self.get_config_attr_or_none("advice.ignoredHook")
            if advice_ignored_hook != 'false':  # both empty and "true" is okay
                # The [33m color must be used to keep consistent with how git colors this advice for its built-in hooks.
                print(colored(f"hint: The '{hook_path}' hook was ignored because it's not set as executable.", AnsiEscapeCodes.YELLOW),
                      file=sys.stderr)
                print(colored("hint: You can disable this warning with `git config advice.ignoredHook false`.", AnsiEscapeCodes.YELLOW),
                      file=sys.stderr)
            return False
        else:
            return True

    def merge(self, branch: LocalBranchShortName,
              into: LocalBranchShortName,
              opt_no_edit_merge: bool
              ) -> None:
        extra_params = ["--no-edit"] if opt_no_edit_merge else ["--edit"]
        # We need to specify the message explicitly to avoid 'refs/heads/' prefix getting into the message...
        commit_message = f"Merge branch '{branch}' into {into}"
        # ...since we prepend 'refs/heads/' to the merged branch name for unambiguity.
        self._run_git("merge", "-m", commit_message, branch.full_name(), *extra_params)
        self.flush_caches()

    def merge_fast_forward_only(self, branch: LocalBranchShortName) -> None:  # refs/heads/ prefix is assumed for 'branch'
        self._run_git("merge", "--ff-only", branch.full_name())
        self.flush_caches()

    def rebase(self, onto: AnyRevision, from_exclusive: AnyRevision, branch: LocalBranchShortName, opt_no_interactive_rebase: bool) -> None:
        def do_rebase() -> None:
            # Let's use `OPTS` suffix for consistency with git's built-in env var `GIT_DIFF_OPTS`
            git_machete_rebase_opts_var = 'GIT_MACHETE_REBASE_OPTS'
            rebase_opts = os.environ.get(git_machete_rebase_opts_var, '').split()
            try:
                if not opt_no_interactive_rebase:
                    rebase_opts.append("--interactive")
                if self.get_git_version() >= (2, 26, 0):
                    rebase_opts.append("--empty=drop")
                self._run_git("rebase", *rebase_opts, "--onto", onto, from_exclusive, branch)
            finally:
                # https://public-inbox.org/git/317468c6-40cc-9f26-8ee3-3392c3908efb@talktalk.net/T
                # In our case, this can happen when git version invoked by git-machete to start the rebase
                # is different than git version used (outside of git-machete) to continue the rebase.
                # This used to be the case when git-machete was installed via a strict-confinement snap
                # with its own version of git baked in as a dependency.
                # Currently we're using classic-confinement snaps which no longer have this problem
                # (snapped git-machete uses whatever git is available in the host system),
                # but it still doesn't harm to patch the author script.

                # No need to fix <git-dir>/rebase-apply/author-script,
                # only <git-dir>/rebase-merge/author-script (i.e. interactive rebases, for the most part) is affected.
                author_script = self.get_worktree_git_subpath("rebase-merge", "author-script")
                if os.path.isfile(author_script):
                    faulty_line_regex = re.compile("[A-Z0-9_]+='[^']*")

                    def fix_if_needed(line: str) -> str:
                        return f"{line.rstrip()}'\n" if faulty_line_regex.fullmatch(line) else line

                    def get_all_lines_fixed() -> Iterator[str]:
                        with open(author_script) as f_read:
                            return map(fix_if_needed, f_read.readlines())

                    fixed_lines = get_all_lines_fixed()  # must happen before the 'with' clause where we open for writing
                    with open(author_script, "w") as f_write:
                        f_write.write("".join(fixed_lines))
                self.flush_caches()

        hook_path = self.get_hook_path("machete-pre-rebase")
        if self.check_hook_executable(hook_path):
            debug(f"running machete-pre-rebase hook ({hook_path})")
            exit_code = utils.run_cmd(hook_path, onto, from_exclusive, branch, cwd=self.get_root_dir())
            if exit_code == 0:
                do_rebase()
            else:
                raise MacheteException(
                    f"The machete-pre-rebase hook refused to rebase. Error code: {exit_code}\n")
        else:
            do_rebase()

    def rebase_onto_ancestor_commit(self,
                                    branch: LocalBranchShortName,
                                    ancestor_revision: AnyRevision,
                                    opt_no_interactive_rebase: bool
                                    ) -> None:
        self.rebase(ancestor_revision, ancestor_revision, branch, opt_no_interactive_rebase)

    def get_commits_between(self, earliest_exclusive: AnyRevision, latest_inclusive: AnyRevision) -> List[GitLogEntry]:
        # Reverse the list, since `git log` by default returns the commits from the latest to earliest.
        return list(reversed(list(map(
            lambda x: GitLogEntry(hash=FullCommitHash(x.split(":", 2)[0]),
                                  short_hash=ShortCommitHash(x.split(":", 2)[1]),
                                  subject=x.split(":", 2)[2]),
            utils.get_non_empty_lines(self._popen_git("log", "--format=%H:%h:%s", f"^{earliest_exclusive}", latest_inclusive, "--").stdout)
        ))))

    def get_relation_to_remote_counterpart(self, branch: LocalBranchShortName, remote_branch: RemoteBranchShortName) -> int:
        b_is_anc_of_rb = self.is_ancestor_or_equal(branch.full_name(), remote_branch.full_name())
        rb_is_anc_of_b = self.is_ancestor_or_equal(remote_branch.full_name(), branch.full_name())
        if b_is_anc_of_rb:
            return SyncToRemoteStatuses.IN_SYNC_WITH_REMOTE if rb_is_anc_of_b else SyncToRemoteStatuses.BEHIND_REMOTE
        elif rb_is_anc_of_b:
            return SyncToRemoteStatuses.AHEAD_OF_REMOTE
        else:
            b_t = self.get_committer_unix_timestamp_by_revision(branch)
            rb_t = self.get_committer_unix_timestamp_by_revision(remote_branch)
            return SyncToRemoteStatuses.DIVERGED_FROM_AND_OLDER_THAN_REMOTE if b_t < rb_t else \
                SyncToRemoteStatuses.DIVERGED_FROM_AND_NEWER_THAN_REMOTE

    def get_strict_remote_sync_status(self, branch: LocalBranchShortName) -> Tuple[int, Optional[str]]:
        if not self.get_remotes():
            return SyncToRemoteStatuses.NO_REMOTES, None
        remote_branch = self.get_strict_counterpart_for_fetching_of_branch(branch)
        if not remote_branch:
            return SyncToRemoteStatuses.UNTRACKED, None
        return self.get_relation_to_remote_counterpart(branch, remote_branch), self.get_strict_remote_for_fetching_of_branch(branch)

    def get_combined_remote_sync_status(self, branch: LocalBranchShortName) -> Tuple[int, Optional[str]]:
        if not self.get_remotes():
            return SyncToRemoteStatuses.NO_REMOTES, None
        remote_branch = self.get_combined_counterpart_for_fetching_of_branch(branch)
        if not remote_branch:
            return SyncToRemoteStatuses.UNTRACKED, None
        return self.get_relation_to_remote_counterpart(branch, remote_branch), self.get_combined_remote_for_fetching_of_branch(branch)

    def get_latest_checkout_timestamps(self) -> Dict[str, int]:  # TODO (#110): default dict with 0
        # Entries are in the format '<branch_name>@{<unix_timestamp> <time-zone>}'
        result = {}
        # %gd - reflog selector (HEAD@{<unix-timestamp> <time-zone>} for `--date=raw`;
        #   `--date=unix` is not available on some older versions of git)
        # %gs - reflog subject
        output = self._popen_git("reflog", "show", "--format=%gd:%gs", "--date=raw").stdout
        for entry in utils.get_non_empty_lines(output):
            pattern = "^HEAD@\\{([0-9]+) .+\\}:checkout: moving from (.+) to (.+)$"  # noqa: FS003
            match = re.search(pattern, entry)
            if match:
                from_branch = match.group(2)
                to_branch = match.group(3)
                # Only the latest occurrence for any given branch is interesting
                # (i.e. the first one to occur in reflog)
                if from_branch not in result:
                    result[from_branch] = int(match.group(1))
                if to_branch not in result:
                    result[to_branch] = int(match.group(1))
        return result

    def get_commit_information(self, commit: AnyRevision, information: GitFormatPatterns) -> str:
        if information not in GitFormatPatterns:
            raise MacheteException(
                f"Retrieving {information} from commit is not supported by project"
                " git-machete. Currently supported information are: "
                f"{', '.join(GitFormatPatterns._member_names_)}")

        params = ["log", "-1", f"--format={information.value}"]
        if commit:
            params.append(commit)
        return self._popen_git(*params).stdout.strip()

    def display_branch_history_from_fork_point(self, branch: LocalBranchFullName, fork_point: FullCommitHash) -> int:
        return self._run_git("log", f"^{fork_point}", branch)

    def commit_tree_with_given_parent_and_message_and_env(
            self, parent_revision: AnyRevision, msg: str, env: Dict[str, str]) -> FullCommitHash:
        # returns hash of the new commit
        return FullCommitHash.of(self._popen_git(
            "commit-tree", "HEAD^{tree}", "-p", parent_revision, "-m", msg, env=env).stdout.strip())  # noqa: FS003

    def delete_branch(self, branch_name: LocalBranchShortName, force: bool = False) -> int:
        self.flush_caches()
        delete_option = '-D' if force else '-d'
        return self._run_git("branch", delete_option, branch_name)

    def display_diff(self, fork_point: AnyRevision, format_with_stat: bool, branch: Optional[LocalBranchShortName] = None) -> int:
        params = ["diff"]
        if format_with_stat:
            params.append("--stat")
        params.append(fork_point)
        if branch:
            params.append(branch.full_name())
        params.append("--")

        return self._run_git(*params)

    def update_head_ref_to_new_hash_with_reflog_subject(self, hash: FullCommitHash, reflog_subject: str) -> int:
        self.flush_caches()
        return self._run_git("update-ref", "HEAD", hash, "-m", reflog_subject)
