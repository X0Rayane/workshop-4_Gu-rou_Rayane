import express from "express";
import bodyParser from "body-parser";
import { REGISTRY_PORT } from "../config";
import {
  generateRsaKeyPair,
  exportPubKey,
  exportPrvKey,
  importPrvKey,
} from "../crypto";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const registeredNodes: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;

    // Check if the node is already registered
    const existingNode = registeredNodes.find((node) => node.nodeId === nodeId);

    if (existingNode) {
      return res
        .status(400)
        .json({ message: `Node ${nodeId} is already registered.` });
    }

    // Add the node to the registered nodes array
    registeredNodes.push({ nodeId, pubKey });
    const nodeRegistry: GetNodeRegistryBody = { nodes: registeredNodes };
    res.json(nodeRegistry);

    return res
      .status(201)
      .json({ message: `Node ${nodeId} successfully registered.` });
  });

  _registry.get("/getNodeRegistry", (req, res) => {
    const nodeRegistry: GetNodeRegistryBody = { nodes: registeredNodes };
    res.json(nodeRegistry);
  });

  _registry.get("/getPrivateKey/:nodeId", async (req, res) => {
    const nodeId = parseInt(req.params.nodeId);
    const node = registeredNodes.find((n) => n.nodeId === nodeId);
    if (!node) {
      return res.status(404).json({ error: "Node not found" });
    }
    try {
      // Import the private key instead of generating a new one
      const prvKey = await generatePrivateKey();
      return res.json({ result: prvKey });
    } catch (error) {
      console.error("Error retrieving private key:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}

async function generatePrivateKey() {
  const keyPair = await generateRsaKeyPair();
  const prvKey = await exportPrvKey(keyPair.privateKey);
  return prvKey;
}
