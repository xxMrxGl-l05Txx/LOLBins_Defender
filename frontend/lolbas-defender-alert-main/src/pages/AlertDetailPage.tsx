import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import AlertDetail from "@/components/alerts/AlertDetail";

const AlertDetailPage = () => {
  const { id } = useParams<{ id: string }>();

  return (
    <div className="mx-auto max-w-3xl">
      <Button variant="ghost" size="sm" className="mb-4 -ml-2 text-muted-foreground" asChild>
        <Link to="/alerts">
          <ArrowLeft />
          Back to alerts
        </Link>
      </Button>
      {id && <AlertDetail alertId={id} variant="page" />}
    </div>
  );
};

export default AlertDetailPage;
