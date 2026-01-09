import { createFromRoot } from "codama";
import { rootNodeFromAnchor } from "@codama/nodes-from-anchor";
import { renderVisitor as renderJavaScriptVisitor } from "@codama/renderers-js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const anchorIdl = JSON.parse(
  fs.readFileSync(
    new URL("../target/idl/gpl_session.json", import.meta.url),
    "utf8"
  )
);

const codama = createFromRoot(rootNodeFromAnchor(anchorIdl));

const jsClient = path.join(__dirname, "..", "clients", "gpl_session");
codama.accept(renderJavaScriptVisitor(path.join(jsClient, "src", "generated")));
