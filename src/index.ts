import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import { isValidSignature, isExpired } from "./helpers/webhookHelper";

const app = express();
const port = 3000;

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET as string;

app.use(bodyParser.text());

app.post("/webhook", (req: any, res: any) => {
    console.log(req.body);

    const signatureFromHeader = req.header("X-Engine-Signature");
    const timestampFromHeader = req.header("X-Engine-Timestamp");

    if (!signatureFromHeader || !timestampFromHeader) {
        return res
        .status(401)
        .send("Missing signature or timestamp header");
    }

    if (
        !isValidSignature(
        req.body,
        timestampFromHeader,
        signatureFromHeader,
        WEBHOOK_SECRET,
        )
    ) {
        return res.status(401).send("Invalid signature");
    }

    if (isExpired(timestampFromHeader, 300)) {
        // Assuming expiration time is 5 minutes (300 seconds)
        return res.status(401).send("Request has expired");
    }

    // Process the request
    res.status(200).send("Webhook received!");
});

app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
});
