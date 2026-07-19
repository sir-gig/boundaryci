import type { Repository } from "../types";
import { CopyButton } from "./CopyButton";
import { RepositorySetupGuide } from "./RepositorySetupGuide";

export function TokenReveal({
  repository,
  token,
  onDone,
}: {
  repository: Repository;
  token: string;
  onDone: () => void;
}) {
  return (
    <section className="onboarding-card token-reveal">
      <div className="success-orb" aria-hidden="true">✓</div>
      <span className="eyebrow">Repository connected</span>
      <h2>Save this token now</h2>
      <p className="muted">
        This is the only time BoundaryCI will display the plaintext token for
        <strong> {repository.full_name}</strong>. Store it as the GitHub Actions secret
        <code> BOUNDARYCI_CLOUD_TOKEN</code>.
      </p>
      <div className="secret-box">
        <code>{token}</code>
        <CopyButton value={token} label="Copy token" />
      </div>
      <RepositorySetupGuide repository={repository} embedded />
      <div className="alert alert-warning">
        BoundaryCI Cloud is in public beta. Begin with a non-production repository and review
        uploaded finding content before wider rollout.
      </div>
      <button className="button button-primary" type="button" onClick={onDone}>
        Open dashboard
      </button>
    </section>
  );
}
