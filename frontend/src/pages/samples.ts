// The bundled sample models (engine/samples on the server). Keys match the API's `sample` choices.
export type SampleKey = "online_shop" | "kubernetes" | "aws";

export interface SampleInfo {
  key: SampleKey;
  title: string;
  body: string;
}

export const SAMPLES: SampleInfo[] = [
  {
    key: "online_shop",
    title: "Online shop",
    body: "Drawn by hand. Shows how stating facts about components changes the threats.",
  },
  {
    key: "kubernetes",
    title: "Kubernetes app",
    body: "Built from uploaded manifests. An exposed service, a cluster-admin workload and a password in a ConfigMap.",
  },
  {
    key: "aws",
    title: "AWS app",
    body: "Built from a Terraform plan. A public database and a bucket anyone can read.",
  },
];
