"use strict";
const express = require("express");
const router = express.Router();
const auth = require("../middlewares/auth");
const ctrl = require("../controllers/transactionsController");

router.get("/", auth, ctrl.list);
router.get("/status", ctrl.statusSummary);
router.get("/:id", auth, ctrl.detail);
router.post("/", auth, ctrl.create);
router.put("/:id", auth, ctrl.update);
router.patch("/:id", auth, ctrl.patch);
router.patch("/:id/status", auth, ctrl.updateStatus);
router.delete("/:id", auth, ctrl.remove);

module.exports = router;
