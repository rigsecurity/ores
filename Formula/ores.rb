class Ores < Formula
  desc "Open Risk Evaluation & Scoring — deterministic cybersecurity risk scoring engine"
  homepage "https://github.com/rigsecurity/ores"
  url "https://github.com/rigsecurity/ores/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "UPDATE_ON_RELEASE"
  license "Apache-2.0"
  head "https://github.com/rigsecurity/ores.git", branch: "main"

  depends_on "go" => :build
  depends_on "buf" => :build

  def install
    system "buf", "generate"
    ldflags = "-s -w"
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/ores"
  end

  test do
    assert_match "ores model version", shell_output("#{bin}/ores version")

    (testpath/"input.json").write <<~JSON
      {
        "apiVersion": "ores.dev/v1",
        "kind": "EvaluationRequest",
        "signals": {
          "cvss": {"base_score": 9.8}
        }
      }
    JSON
    output = shell_output("#{bin}/ores evaluate -f #{testpath}/input.json -o json")
    assert_match '"kind": "EvaluationResult"', output
  end
end
