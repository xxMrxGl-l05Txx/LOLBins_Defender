import { PageHeader } from "@/components/common/PageHeader";
import RuleList from "@/components/rules/RuleList";
import RuleTester from "@/components/rules/RuleTester";

const Rules = () => (
  <>
    <PageHeader
      eyebrow="console / detection rules"
      title="Detection rules"
      description="The LOLBin signatures the monitor applies to every process, mapped to MITRE ATT&CK. Use the tester to check a command line safely."
    />
    <div className="grid items-start gap-4 lg:grid-cols-5 lg:gap-5">
      <div className="lg:col-span-3">
        <RuleList />
      </div>
      <div className="lg:col-span-2">
        <RuleTester />
      </div>
    </div>
  </>
);

export default Rules;
