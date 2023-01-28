package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/felixge/fgprof"
	"github.com/gorilla/mux"
	"github.com/jpillora/overseer"
	"github.com/mattn/go-isatty"
	"github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cli"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui"
	"github.com/trufflesecurity/trufflehog/v3/pkg/updater"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

var cmd string

func init() {
	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "--") {
			split := strings.SplitN(arg, "=", 2)
			split[0] = strings.ReplaceAll(split[0], "_", "-")
			os.Args[i] = strings.Join(split, "=")
		}
	}

	cli.CLI.Version("trufflehog " + version.BuildVersion)

	commands := os.Args[1:]
	if len(os.Args) <= 1 && isatty.IsTerminal(os.Stdout.Fd()) {
		commands = tui.Run()
	}

	cmd = kingpin.MustParse(cli.CLI.Parse(commands))

	if *cli.JsonOut {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
	switch {
	case *cli.Trace:
		log.SetLevel(5)
		logrus.SetLevel(logrus.TraceLevel)
		logrus.Debugf("running version %s", version.BuildVersion)
	case *cli.Debug:
		log.SetLevel(2)
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debugf("running version %s", version.BuildVersion)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
}

func main() {
	updateCfg := overseer.Config{
		Program:       run,
		Debug:         *cli.Debug,
		RestartSignal: syscall.SIGTERM,
		// TODO: Eventually add a PreUpgrade func for signature check w/ x509 PKCS1v15
		// PreUpgrade: checkUpdateSignature(binaryPath string),
	}

	if !*cli.NoUpdate {
		updateCfg.Fetcher = updater.Fetcher(version.BuildVersion)
	}
	if version.BuildVersion == "dev" {
		updateCfg.Fetcher = nil
	}

	err := overseer.RunErr(updateCfg)
	if err != nil {
		logrus.WithError(err).Fatal("error occured with trufflehog updater 🐷")
	}
}

func run(state overseer.State) {
	if *cli.Debug {
		logrus.Debugf("trufflehog %s", version.BuildVersion)
	}

	if *cli.GithubScanToken != "" {
		// NOTE: this kludge is here to do an authenticated shallow commit
		// TODO: refactor to better pass credentials
		os.Setenv("GITHUB_TOKEN", *cli.GithubScanToken)
	}

	// When setting a base commit, chunks must be scanned in order.
	if *cli.GitScanSinceCommit != "" {
		*cli.Concurrency = 1
	}

	if *cli.Debug {
		go func() {
			router := mux.NewRouter()
			router.PathPrefix("/debug/pprof").Handler(http.DefaultServeMux)
			router.PathPrefix("/debug/fgprof").Handler(fgprof.Handler())
			logrus.Info("starting pprof and fgprof server on :18066 /debug/pprof and /debug/fgprof")
			if err := http.ListenAndServe(":18066", router); err != nil {
				logrus.Error(err)
			}
		}()
	}
	logger, sync := log.New("trufflehog", log.WithConsoleSink(os.Stderr))
	context.SetDefaultLogger(logger)
	defer func() { _ = sync() }()

	conf := &config.Config{}
	if *cli.ConfigFilename != "" {
		var err error
		conf, err = config.Read(*cli.ConfigFilename)
		if err != nil {
			logger.Error(err, "error parsing the provided configuration file")
			os.Exit(1)
		}
	}

	ctx := context.TODO()
	e := engine.Start(ctx,
		engine.WithConcurrency(*cli.Concurrency),
		engine.WithDecoders(decoders.DefaultDecoders()...),
		engine.WithDetectors(!*cli.NoVerification, engine.DefaultDetectors()...),
		engine.WithDetectors(!*cli.NoVerification, conf.Detectors...),
		engine.WithFilterUnverified(*cli.FilterUnverified),
	)

	filter, err := common.FilterFromFiles(*cli.GitScanIncludePaths, *cli.GitScanExcludePaths)
	if err != nil {
		logrus.WithError(err).Fatal("could not create filter")
	}

	var repoPath string
	var remote bool
	switch cmd {
	case cli.GitScan.FullCommand():
		repoPath, remote, err = git.PrepareRepoSinceCommit(ctx, *cli.GitScanURI, *cli.GitScanSinceCommit)
		if err != nil || repoPath == "" {
			logrus.WithError(err).Fatal("error preparing git repo for scanning")
		}
		if remote {
			defer os.RemoveAll(repoPath)
		}

		g := func(c *sources.Config) {
			c.RepoPath = repoPath
			c.HeadRef = *cli.GitScanBranch
			c.BaseRef = *cli.GitScanSinceCommit
			c.MaxDepth = *cli.GitScanMaxDepth
			c.Filter = filter
		}

		if err = e.ScanGit(ctx, sources.NewConfig(g)); err != nil {
			logrus.WithError(err).Fatal("Failed to scan Git.")
		}
	case cli.GithubScan.FullCommand():
		if len(*cli.GithubScanOrgs) == 0 && len(*cli.GithubScanRepos) == 0 {
			logrus.Fatal("You must specify at least one organization or repository.")
		}

		github := func(c *sources.Config) {
			c.Endpoint = *cli.GithubScanEndpoint
			c.Repos = *cli.GithubScanRepos
			c.Orgs = *cli.GithubScanOrgs
			c.Token = *cli.GithubScanToken
			c.IncludeForks = *cli.GithubIncludeForks
			c.IncludeMembers = *cli.GithubIncludeMembers
			c.Concurrency = *cli.Concurrency
			c.ExcludeRepos = *cli.GithubExcludeRepos
			c.IncludeRepos = *cli.GithubIncludeRepos
		}

		if err = e.ScanGitHub(ctx, sources.NewConfig(github)); err != nil {
			logrus.WithError(err).Fatal("Failed to scan Github.")
		}
	case cli.GitlabScan.FullCommand():
		filter, err := common.FilterFromFiles(*cli.GitlabScanIncludePaths, *cli.GitlabScanExcludePaths)
		if err != nil {
			logrus.WithError(err).Fatal("could not create filter")
		}

		gitlab := func(c *sources.Config) {
			c.Endpoint = *cli.GitlabScanEndpoint
			c.Token = *cli.GitlabScanToken
			c.Repos = *cli.GitlabScanRepos
			c.Filter = filter
		}

		if err = e.ScanGitLab(ctx, sources.NewConfig(gitlab)); err != nil {
			logrus.WithError(err).Fatal("Failed to scan GitLab.")
		}
	case cli.FilesystemScan.FullCommand():
		os.Exit(1)
		fs := func(c *sources.Config) {
			c.Directories = *cli.FilesystemDirectories
		}

		if err = e.ScanFileSystem(ctx, sources.NewConfig(fs)); err != nil {
			logrus.WithError(err).Fatal("Failed to scan filesystem")
		}
	case cli.S3Scan.FullCommand():
		s3 := func(c *sources.Config) {
			c.Key = *cli.S3ScanKey
			c.Secret = *cli.S3ScanSecret
			c.Buckets = *cli.S3ScanBuckets
		}

		if err = e.ScanS3(ctx, sources.NewConfig(s3)); err != nil {
			logrus.WithError(err).Fatal("Failed to scan S3.")
		}
	case cli.SyslogScan.FullCommand():
		syslog := func(c *sources.Config) {
			c.Address = *cli.SyslogAddress
			c.Protocol = *cli.SyslogProtocol
			c.CertPath = *cli.SyslogTLSCert
			c.KeyPath = *cli.SyslogTLSKey
			c.Format = *cli.SyslogFormat
			c.Concurrency = *cli.Concurrency
		}

		if err = e.ScanSyslog(ctx, sources.NewConfig(syslog)); err != nil {
			logrus.WithError(err).Fatal("Failed to scan syslog.")
		}
	case cli.CircleCiScan.FullCommand():
		if err = e.ScanCircleCI(ctx, *cli.CircleCiScanToken); err != nil {
			logrus.WithError(err).Fatal("Failed to scan CircleCI.")
		}
	}
	// asynchronously wait for scanning to finish and cleanup
	go e.Finish(ctx)

	if !*cli.JsonLegacy && !*cli.JsonOut {
		fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")
	}

	// NOTE: this loop will terminate when the results channel is closed in
	// e.Finish()
	foundResults := false
	for r := range e.ResultsChan() {
		if *cli.OnlyVerified && !r.Verified {
			continue
		}
		foundResults = true

		switch {
		case *cli.JsonLegacy:
			output.PrintLegacyJSON(ctx, &r)
		case *cli.JsonOut:
			output.PrintJSON(&r)
		default:
			output.PrintPlainOutput(&r)
		}
	}
	logrus.Debugf("scanned %d chunks", e.ChunksScanned())
	logrus.Debugf("scanned %d bytes", e.BytesScanned())

	if *cli.PrintAvgDetectorTime {
		printAverageDetectorTime(e)
	}

	if foundResults && *cli.Fail {
		logrus.Debug("exiting with code 183 because results were found")
		os.Exit(183)
	}
}

func printAverageDetectorTime(e *engine.Engine) {
	fmt.Fprintln(os.Stderr, "Average detector time is the measurement of average time spent on each detector when results are returned.")
	for detectorName, durations := range e.DetectorAvgTime() {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avgDuration := total / time.Duration(len(durations))
		fmt.Fprintf(os.Stderr, "%s: %s\n", detectorName, avgDuration)
	}
}
