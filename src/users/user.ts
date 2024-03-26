import express from "express";
import bodyParser from "body-parser";
import { GetNodeRegistryBody, Node } from "../registry/registry";
import {
  BASE_USER_PORT,
  BASE_ONION_ROUTER_PORT,
  REGISTRY_PORT,
} from "../config";
import {
  createRandomSymmetricKey,
  symEncrypt,
  rsaEncrypt,
  exportSymKey,
} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

interface RegistryResponse {
  nodes: Node[];
}

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // Variables to store the last received and last sent messages
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: Node[] = [];

  // Route to receive messages
  _user.post("/message", (req, res) => {
    const { message }: { message: string } = req.body;
    console.log(`User ${userId} received message: ${message}`);
    lastReceivedMessage = message;
    res.send("success");
  });

  // Route to retrieve the last received message
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Route to retrieve the last sent message
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Route pour obtenir le dernier circuit
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ status: 200, result: lastCircuit.map((node) => node.nodeId) });
  });

  _user.post("/message", (req, res) => {
    const message = req.body.message;

    lastReceivedMessage = message;

    console.log(`Received message: ${message}`);

    // Send a success response
    res.status(200).send("success");
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;

    // Obtenez la liste des nœuds disponibles dans le réseau
    const response = await fetch(
      `http://localhost:${REGISTRY_PORT}/getNodeRegistry`
    );
    const nodes = await fetch(
      `http://localhost:${REGISTRY_PORT}/getNodeRegistry`
    )
      .then((res) => res.json())
      .then((body: any) => body.nodes);

    // Créez un circuit de 3 nœuds à partir de la liste des nœuds disponibles
    let circuit: Node[] = [];
    while (circuit.length < 3) {
      const randomNode = nodes[Math.floor(Math.random() * nodes.length)];
      if (!circuit.find((node) => node.nodeId === randomNode.nodeId)) {
        circuit.push(randomNode);
      }
    }

    // Préparez le message à envoyer
    let finalMessage = message;
    let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");

    // Chiffrez le message pour chaque nœud dans le circuit
    for (let i = circuit.length - 1; i >= 0; i--) {
      const node = circuit[i];
      const symmetricKey = await createRandomSymmetricKey();
      const symmetricKey64 = await exportSymKey(symmetricKey);
      finalMessage = await symEncrypt(symmetricKey, destination + finalMessage);
      const encryptedSymKey = await rsaEncrypt(symmetricKey64, node.pubKey);
      finalMessage = encryptedSymKey + finalMessage;
      destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, "0");
    }

    lastCircuit = circuit.reverse();
    lastSentMessage = message;

    // Envoyez le message final au premier nœud du circuit
    await fetch(`http://localhost:${destination}/message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: finalMessage }),
    });

    res.status(200).send("Message envoyé avec succès.");
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
