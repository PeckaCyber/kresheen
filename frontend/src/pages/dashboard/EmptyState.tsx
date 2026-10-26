import { Link } from "react-router-dom";

export function EmptyState() {
  return (
    <section className="pc-panel pc-empty-hero" aria-label="No applications yet">
      <div className="pc-panel-body text-center py-5">
        <h2 className="h5 mb-2">Create your first threat model</h2>
        <p className="text-muted mb-4">
          Once you add a model and give it a data source or two, this page fills in with the trends, risk and progress
          across everything you can see.
        </p>
        <Link to="/applications" className="btn btn-primary">
          Create your first threat model
        </Link>
      </div>
    </section>
  );
}
