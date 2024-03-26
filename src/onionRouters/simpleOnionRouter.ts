import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import {
  generateRsaKeyPair,
  exportPrvKey,
  exportPubKey,
  rsaDecrypt,
  symDecrypt,
  importPrvKey,
} from "../crypto";
import { Node, RegisterNodeBody } from "../registry/registry";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  const { privateKey, publicKey } = await generateRsaKeyPair();
  const publicKeyStr = await exportPubKey(publicKey);

  const registerNode: RegisterNodeBody = {
    nodeId: nodeId,
    pubKey: publicKeyStr,
  };

  const registryUrl = `http://localhost:${REGISTRY_PORT}/registerNode`;
  try {
    await fetch(registryUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(registerNode),
    });
    console.log(`Node ${nodeId} successfully registered.`);
  } catch (error) {
    console.error(`Failed to register Node ${nodeId}: `);
  }

  // status route
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // last received decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // last message destination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    try {
      const privateKeyStr = await exportPrvKey(privateKey);
      res.json({ result: privateKeyStr });
    } catch (error) {
      res.status(500).json({ error: "Failed " });
    }
  });

  onionRouter.post("/message", async (req, res) => {
    try {
      const { message } = req.body;
      // Décryptez la clé symétrique (les premiers 344 caractères) avec notre clé privée RSA
      const encryptedSymKey = message.slice(0, 344);
      const symKey = await rsaDecrypt(encryptedSymKey, privateKey);

      // Décryptez le reste du message avec notre clé symétrique
      const encryptedMessage = message.slice(344);
      const decryptedMessage = await symDecrypt(symKey, encryptedMessage);

      // Les 10 premiers caractères du message décrypté représentent l'identifiant de la prochaine destination dans le réseau
      const nextDestination = parseInt(decryptedMessage.slice(0, 10), 10);
      // Le reste du message est extrait après ces 10 premiers caractères
      const remainingMessage = decryptedMessage.slice(10);

      // Mise à jour des informations
      lastReceivedEncryptedMessage = message;
      lastReceivedDecryptedMessage = remainingMessage;
      lastMessageDestination = nextDestination;

      // Envoi de ces informations au prochain nœud dans le réseau anonyme via une requête HTTP POST à l'URL correspondant à la prochaine destination
      await fetch(`http://localhost:${nextDestination}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ message: remainingMessage }),
      });

      res.status(200).send("Message traité avec succès.");
    } catch (error) {
      console.error("Erreur lors du traitement du message:", error);
      res.status(500).send("Erreur lors du traitement du message.");
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
