package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/asset-probe/internal/data"
	"github.com/asset-probe/internal/engine"
	"github.com/asset-probe/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	config  *engine.Config
)

var rootCmd = &cobra.Command{
	Use:   "probe",
	Short: "高性能网络资产探测工具",
	Long: `资产探测工具 - 参考 nmap 和 masscan 实现的高性能网络扫描器
支持大规模网络主机发现、端口扫描、服务识别和代答资产检测。`,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "执行网络扫描",
	Long:  `对目标网络进行主机发现、端口扫描和服务识别`,
	Run:   runScan,
}

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "仅执行主机发现",
	Long:  `仅对目标网络进行主机存活探测`,
	Run:   runDiscover,
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "分析扫描结果",
	Long:  `分析已有扫描结果，识别代答资产`,
	Run:   runAnalyze,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "配置文件路径 (默认为 ./config/config.yaml)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(analyzeCmd)

	initScanFlags()
	initDiscoverFlags()
	initAnalyzeFlags()
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("./config")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "[INFO] 使用配置文件: %s\n", viper.ConfigFileUsed())
	}
}

func initScanFlags() {
	scanCmd.Flags().StringSliceP("target", "t", []string{}, "目标网络范围 (CIDR格式，支持多个)")
	scanCmd.Flags().StringP("ports", "p", "1-65535", "端口范围 (如: 1-1000, 80,443,8080)")
	scanCmd.Flags().IntP("rate", "r", 10000, "发包速率 (PPS)")
	scanCmd.Flags().IntP("concurrency", "c", 1000, "并发数")
	scanCmd.Flags().Duration("timeout", 3*time.Second, "响应超时时间")
	scanCmd.Flags().StringP("output", "o", "result.json", "输出文件路径")
	scanCmd.Flags().StringP("format", "f", "json", "输出格式 (json/csv/xml)")
	scanCmd.Flags().Bool("resume", false, "恢复上次扫描")
	scanCmd.Flags().String("scan-type", "full", "扫描类型 (full/quick/custom)")
	scanCmd.Flags().StringP("interface", "i", "", "网络接口")
	scanCmd.Flags().Bool("service-detection", true, "是否进行服务识别")
	scanCmd.Flags().Bool("proxy-detection", true, "是否进行代答检测")

	_ = scanCmd.MarkFlagRequired("target")
}

func initDiscoverFlags() {
	discoverCmd.Flags().StringSliceP("target", "t", []string{}, "目标网络范围 (CIDR格式，支持多个)")
	discoverCmd.Flags().IntP("rate", "r", 10000, "发包速率 (PPS)")
	discoverCmd.Flags().Duration("timeout", 3*time.Second, "响应超时时间")
	discoverCmd.Flags().StringP("output", "o", "hosts.json", "输出文件路径")
	discoverCmd.Flags().StringP("interface", "i", "", "网络接口")
	discoverCmd.Flags().StringSlice("method", []string{"icmp", "tcp"}, "发现方法 (icmp/tcp/arp)")

	_ = discoverCmd.MarkFlagRequired("target")
}

func initAnalyzeFlags() {
	analyzeCmd.Flags().StringP("input", "i", "result.json", "扫描结果文件路径")
	analyzeCmd.Flags().StringP("output", "o", "analysis.json", "分析结果输出路径")
	analyzeCmd.Flags().Int("subnet-threshold", 254, "C段存活阈值 (用于代答检测)")
	analyzeCmd.Flags().Int("ttl-threshold", 3, "TTL差异阈值")
}

func runScan(cmd *cobra.Command, args []string) {
	targets, _ := cmd.Flags().GetStringSlice("target")
	ports, _ := cmd.Flags().GetString("ports")
	rate, _ := cmd.Flags().GetInt("rate")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	resume, _ := cmd.Flags().GetBool("resume")
	scanType, _ := cmd.Flags().GetString("scan-type")
	iface, _ := cmd.Flags().GetString("interface")
	serviceDetection, _ := cmd.Flags().GetBool("service-detection")
	proxyDetection, _ := cmd.Flags().GetBool("proxy-detection")

	maxIPs := 2 << 23
	if err := utils.ValidateTargetSize(targets, maxIPs); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}

	config = &engine.Config{
		Targets:          targets,
		PortRange:        ports,
		Rate:             rate,
		Concurrency:      concurrency,
		Timeout:          timeout,
		OutputFile:       output,
		OutputFormat:     format,
		Resume:           resume,
		ScanType:         scanType,
		Interface:        iface,
		ServiceDetection: serviceDetection,
		ProxyDetection:   proxyDetection,
	}

	scheduler := engine.NewScheduler(config)
	if err := scheduler.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] 扫描失败: %v\n", err)
		os.Exit(1)
	}
}

func runDiscover(cmd *cobra.Command, args []string) {
	targets, _ := cmd.Flags().GetStringSlice("target")
	rate, _ := cmd.Flags().GetInt("rate")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	output, _ := cmd.Flags().GetString("output")
	iface, _ := cmd.Flags().GetString("interface")
	methods, _ := cmd.Flags().GetStringSlice("method")

	config = &engine.Config{
		Targets:          targets,
		Rate:             rate,
		Timeout:          timeout,
		OutputFile:       output,
		Interface:        iface,
		DiscoveryOnly:    true,
		DiscoveryMethods: methods,
	}

	discovery := engine.NewDiscoveryEngine(config)
	if err := discovery.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] 主机发现失败: %v\n", err)
		os.Exit(1)
	}
}

func runAnalyze(cmd *cobra.Command, args []string) {
	input, _ := cmd.Flags().GetString("input")
	output, _ := cmd.Flags().GetString("output")
	subnetThreshold, _ := cmd.Flags().GetInt("subnet-threshold")
	ttlThreshold, _ := cmd.Flags().GetInt("ttl-threshold")

	results, err := data.LoadResults(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] 加载扫描结果失败: %v\n", err)
		os.Exit(1)
	}

	analyzer := engine.NewProxyAnalyzer(&engine.ProxyAnalyzerConfig{
		SubnetThreshold: subnetThreshold,
		TTLThreshold:    ttlThreshold,
	})

	analysis := analyzer.Analyze(results)
	if err := data.SaveAnalysis(output, analysis); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] 保存分析结果失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[INFO] 分析完成，结果已保存到: %s\n", output)
}

func Execute() error {
	return rootCmd.Execute()
}
