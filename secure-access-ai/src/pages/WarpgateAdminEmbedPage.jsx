import { useEffect } from "react";

import { logSecureAccessEvent } from "../api/audit";
import WarpgateAdminFrame from "../components/WarpgateAdminFrame";
import DashboardLayout from "../layouts/DashboardLayout";
import "../styles/AdminPages.css";

export default function WarpgateAdminEmbedPage({
  title,
  description,
  warpgatePath,
}) {
  useEffect(() => {
    void logSecureAccessEvent("administration", "warpgate.page.opened", {
      page: warpgatePath,
    });
  }, [warpgatePath]);

  return (
    <DashboardLayout>
      <div className="admin-page-header">
        <div>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
      </div>
      <section className="admin-panel warpgate-admin-embed">
        <WarpgateAdminFrame
          className="warpgate-admin-embed-frame"
          src={`/@warpgate/admin#${warpgatePath}`}
          title={`SecureAccess ${title}`}
        />
      </section>
    </DashboardLayout>
  );
}
