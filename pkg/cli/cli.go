package cli

import (
	"runtime"
	"strconv"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	CLI              = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")
	Debug            = CLI.Flag("debug", "Run in debug mode.").Bool()
	Trace            = CLI.Flag("trace", "Run in trace mode.").Bool()
	JsonOut          = CLI.Flag("json", "Output in JSON format.").Short('j').Bool()
	JsonLegacy       = CLI.Flag("json-legacy", "Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.").Bool()
	Concurrency      = CLI.Flag("concurrency", "Number of concurrent workers.").Default(strconv.Itoa(runtime.NumCPU())).Int()
	NoVerification   = CLI.Flag("no-verification", "Don't verify the results.").Bool()
	OnlyVerified     = CLI.Flag("only-verified", "Only output verified results.").Bool()
	FilterUnverified = CLI.Flag("filter-unverified", "Only output first unverified result per chunk per detector if there are more than one results.").Bool()
	ConfigFilename   = CLI.Flag("config", "Path to configuration file.").ExistingFile()
	// rules = CLI.Flag("rules", "Path to file with custom rules.").String()
	PrintAvgDetectorTime = CLI.Flag("print-avg-detector-time", "Print the average time spent on each detector.").Bool()
	NoUpdate             = CLI.Flag("no-update", "Don't check for updates.").Bool()
	Fail                 = CLI.Flag("fail", "Exit with code 183 if results are found.").Bool()

	GitScan             = CLI.Command("git", "Find credentials in git repositories.")
	GitScanURI          = GitScan.Arg("uri", "Git repository URL. https://, file://, or ssh:// schema expected.").Required().String()
	GitScanIncludePaths = GitScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	GitScanExcludePaths = GitScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	GitScanSinceCommit  = GitScan.Flag("since-commit", "Commit to start scan from.").String()
	GitScanBranch       = GitScan.Flag("branch", "Branch to scan.").String()
	GitScanMaxDepth     = GitScan.Flag("max-depth", "Maximum depth of commits to scan.").Int()
	_                   = GitScan.Flag("allow", "No-op flag for backwards compat.").Bool()
	_                   = GitScan.Flag("entropy", "No-op flag for backwards compat.").Bool()
	_                   = GitScan.Flag("regex", "No-op flag for backwards compat.").Bool()

	GithubScan           = CLI.Command("github", "Find credentials in GitHub repositories.")
	GithubScanEndpoint   = GithubScan.Flag("endpoint", "GitHub endpoint.").Default("https://api.github.com").String()
	GithubScanRepos      = GithubScan.Flag("repo", `GitHub repository to scan. You can repeat this flag. Example: "https://github.com/dustin-decker/secretsandstuff"`).Strings()
	GithubScanOrgs       = GithubScan.Flag("org", `GitHub organization to scan. You can repeat this flag. Example: "trufflesecurity"`).Strings()
	GithubScanToken      = GithubScan.Flag("token", "GitHub token. Can be provided with environment variable GITHUB_TOKEN.").Envar("GITHUB_TOKEN").String()
	GithubIncludeForks   = GithubScan.Flag("include-forks", "Include forks in scan.").Bool()
	GithubIncludeMembers = GithubScan.Flag("include-members", "Include organization member repositories in scan.").Bool()
	GithubIncludeRepos   = GithubScan.Flag("include-repos", `Repositories to include in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Github repo full name. Example: "trufflesecurity/trufflehog", "trufflesecurity/t*"`).Strings()
	GithubExcludeRepos   = GithubScan.Flag("exclude-repos", `Repositories to exclude in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Github repo full name. Example: "trufflesecurity/driftwood", "trufflesecurity/d*"`).Strings()

	GitlabScan = CLI.Command("gitlab", "Find credentials in GitLab repositories.")
	// TODO: Add more GitLab options
	GitlabScanEndpoint     = GitlabScan.Flag("endpoint", "GitLab endpoint.").Default("https://gitlab.com").String()
	GitlabScanRepos        = GitlabScan.Flag("repo", "GitLab repo url. You can repeat this flag. Leave empty to scan all repos accessible with provided credential. Example: https://gitlab.com/org/repo.git").Strings()
	GitlabScanToken        = GitlabScan.Flag("token", "GitLab token. Can be provided with environment variable GITLAB_TOKEN.").Envar("GITLAB_TOKEN").Required().String()
	GitlabScanIncludePaths = GitlabScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	GitlabScanExcludePaths = GitlabScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()

	FilesystemScan        = CLI.Command("filesystem", "Find credentials in a filesystem.")
	FilesystemDirectories = FilesystemScan.Flag("directory", "Path to directory to scan. You can repeat this flag.").Required().Strings()
	// TODO: Add more filesystem scan options. Currently only supports scanning a list of directories.
	// filesystemScanRecursive = filesystemScan.Flag("recursive", "Scan recursively.").Short('r').Bool()
	// filesystemScanIncludePaths = filesystemScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	// filesystemScanExcludePaths = filesystemScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()

	S3Scan         = CLI.Command("s3", "Find credentials in S3 buckets.")
	S3ScanKey      = S3Scan.Flag("key", "S3 key used to authenticate. Can be provided with environment variable AWS_ACCESS_KEY_ID.").Envar("AWS_ACCESS_KEY_ID").String()
	S3ScanSecret   = S3Scan.Flag("secret", "S3 secret used to authenticate. Can be provided with environment variable AWS_SECRET_ACCESS_KEY.").Envar("AWS_SECRET_ACCESS_KEY").String()
	S3ScanCloudEnv = S3Scan.Flag("cloud-environment", "Use IAM credentials in cloud environment.").Bool()
	S3ScanBuckets  = S3Scan.Flag("bucket", "Name of S3 bucket to scan. You can repeat this flag.").Strings()

	SyslogScan     = CLI.Command("syslog", "Scan syslog")
	SyslogAddress  = SyslogScan.Flag("address", "Address and port to listen on for syslog. Example: 127.0.0.1:514").String()
	SyslogProtocol = SyslogScan.Flag("protocol", "Protocol to listen on. udp or tcp").String()
	SyslogTLSCert  = SyslogScan.Flag("cert", "Path to TLS cert.").String()
	SyslogTLSKey   = SyslogScan.Flag("key", "Path to TLS key.").String()
	SyslogFormat   = SyslogScan.Flag("format", "Log format. Can be rfc3164 or rfc5424").String()

	CircleCiScan      = CLI.Command("circleci", "Scan CircleCI")
	CircleCiScanToken = CircleCiScan.Flag("token", "CircleCI token. Can also be provided with environment variable").Envar("CIRCLECI_TOKEN").Required().String()
)
