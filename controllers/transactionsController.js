"use strict";
const { Transaction } = require("../models");

exports.list = async function list(req, res, next) {
  try {
    const userId = req.user && req.user.id;
    const rows = await Transaction.findAll({
      where: userId ? { userId } : {},
      order: [["id", "DESC"]],
      limit: 50,
      attributes: [
        "id",
        "invoiceId",
        "method",
        "status",
        "billingFirstName",
        "billingCity",
        "billingEmail",
        "billingDate",
        "dueDate",
        "subtotal",
        "shipping",
        "total",
        "createdAt",
      ],
    });
    res.json({ transactions: rows });
  } catch (err) {
    next(err);
  }
};

exports.detail = async function detail(req, res, next) {
  try {
    const idParam = req.params.id;
    const where = /^\d+$/.test(idParam) ? { id: Number(idParam) } : { invoiceId: idParam };
    const item = await Transaction.findOne({ where });
    if (!item) return res.status(404).json({ message: "Transaction not found" });
    res.json(item);
  } catch (err) {
    next(err);
  }
};

exports.create = async function create(req, res, next) {
  try {
    const userId = req.user && req.user.id;
    const {
      invoiceId,
      method,
      status = "pending",
      billing = {},
      billingDate,
      dueDate,
      items,
      subtotal = 0,
      shipping = 0,
      total = 0,
    } = req.body || {};

    if (!invoiceId || !method || !billingDate || !Array.isArray(items)) {
      return res.status(400).json({ message: "invoiceId, method, billingDate, and items are required" });
    }

    const payload = {
      userId: userId || null,
      invoiceId,
      method,
      status: String(status || "pending"),
      billingFirstName: billing.firstName || null,
      billingStreet: billing.street || null,
      billingApt: billing.apt || null,
      billingCity: billing.city || null,
      billingPhone: billing.phone || null,
      billingEmail: billing.email || null,
      billingDate: new Date(billingDate),
      dueDate: dueDate ? new Date(dueDate) : null,
      itemsJson: JSON.stringify(items),
      subtotal: Number(subtotal) || 0,
      shipping: Number(shipping) || 0,
      total: Number(total) || 0,
    };

    const created = await Transaction.create(payload);
    res.status(201).json({ id: created.id, invoiceId: created.invoiceId });
  } catch (err) {
    next(err);
  }
};

exports.update = async function update(req, res, next) {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "invalid id" });
    const item = await Transaction.findOne({ where: { id } });
    if (!item) return res.status(404).json({ message: "Transaction not found" });
    const {
      invoiceId,
      method,
      status,
      billing = {},
      billingDate,
      dueDate,
      items,
      subtotal,
      shipping,
      total,
    } = req.body || {};
    const payload = {};
    if (invoiceId != null) payload.invoiceId = String(invoiceId);
    if (method != null) payload.method = String(method);
    if (status != null) payload.status = String(status);
    if (billing != null && typeof billing === "object") {
      if (billing.firstName != null) payload.billingFirstName = billing.firstName;
      if (billing.street != null) payload.billingStreet = billing.street;
      if (billing.apt != null) payload.billingApt = billing.apt;
      if (billing.city != null) payload.billingCity = billing.city;
      if (billing.phone != null) payload.billingPhone = billing.phone;
      if (billing.email != null) payload.billingEmail = billing.email;
    }
    if (billingDate != null) payload.billingDate = new Date(billingDate);
    if (dueDate != null) payload.dueDate = dueDate ? new Date(dueDate) : null;
    if (Array.isArray(items)) payload.itemsJson = JSON.stringify(items);
    if (subtotal != null) payload.subtotal = Number(subtotal) || 0;
    if (shipping != null) payload.shipping = Number(shipping) || 0;
    if (total != null) payload.total = Number(total) || 0;
    await Transaction.update(payload, { where: { id } });
    const updated = await Transaction.findOne({
      where: { id },
      attributes: [
        "id",
        "invoiceId",
        "method",
        "status",
        "billingFirstName",
        "billingCity",
        "billingEmail",
        "billingDate",
        "dueDate",
        "subtotal",
        "shipping",
        "total",
        "createdAt",
      ],
    });
    res.json(updated);
  } catch (err) {
    next(err);
  }
};

exports.patch = async function patch(req, res, next) {
  return exports.update(req, res, next);
};

exports.statusSummary = async function statusSummary(req, res, next) {
  try {
    const userId = req.user && req.user.id;
    const baseWhere = userId ? { userId } : {};
    const [pending, paid, failed] = await Promise.all([
      Transaction.count({ where: { ...baseWhere, status: "pending" } }),
      Transaction.count({ where: { ...baseWhere, status: "paid" } }),
      Transaction.count({ where: { ...baseWhere, status: "failed" } }),
    ]);
    res.json({ pending, paid, failed });
  } catch (err) {
    next(err);
  }
};

exports.updateStatus = async function updateStatus(req, res, next) {
  try {
    const idParam = req.params.id;
    const { status } = req.body || {};
    const valid = ["pending", "paid", "failed"];
    if (!status || !valid.includes(String(status))) {
      return res.status(400).json({ message: "invalid status" });
    }
    const where = /^\d+$/.test(idParam) ? { id: Number(idParam) } : { invoiceId: idParam };
    const exists = await Transaction.findOne({ where, attributes: ["id"] });
    if (!exists) return res.status(404).json({ message: "Transaction not found" });
    await Transaction.update({ status: String(status) }, { where });
    const updated = await Transaction.findOne({ where, attributes: ["id", "invoiceId", "status"] });
    res.json(updated);
  } catch (err) {
    next(err);
  }
};

exports.remove = async function remove(req, res, next) {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "invalid id" });
    const item = await Transaction.findOne({ where: { id }, attributes: ["id"] });
    if (!item) return res.status(404).json({ message: "Transaction not found" });
    await Transaction.destroy({ where: { id } });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
};
