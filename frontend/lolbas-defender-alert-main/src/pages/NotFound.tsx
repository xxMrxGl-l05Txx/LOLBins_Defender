import { Link, useLocation } from "react-router-dom";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error("404: no route for", location.pathname);
  }, [location.pathname]);

  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <div className="font-mono text-5xl font-medium tabular">404</div>
      <p className="mt-3 text-[13px] text-muted-foreground">
        No console page matches <code className="font-mono">{location.pathname}</code>.
      </p>
      <Button className="mt-6" asChild>
        <Link to="/">Back to overview</Link>
      </Button>
    </div>
  );
};

export default NotFound;
