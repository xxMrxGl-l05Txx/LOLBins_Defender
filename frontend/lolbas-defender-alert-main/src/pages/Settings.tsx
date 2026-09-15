import { PageHeader } from "@/components/common/PageHeader";
import SettingsForm from "@/components/settings/SettingsForm";

const Settings = () => (
  <>
    <PageHeader
      eyebrow="console / settings"
      title="Settings"
      description="Tune detection, thresholds and notifications. Changes are saved to config.json and applied from the next scan."
    />
    <SettingsForm />
  </>
);

export default Settings;
