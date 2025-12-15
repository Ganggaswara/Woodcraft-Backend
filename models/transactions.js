"use strict";
const { DataTypes } = require("sequelize");

module.exports = (sequelize) => {
  const Transaction = sequelize.define(
    "Transaction",
    {
      id: { type: DataTypes.INTEGER.UNSIGNED, primaryKey: true, autoIncrement: true },
      userId: { type: DataTypes.INTEGER.UNSIGNED, allowNull: true },
      invoiceId: { type: DataTypes.STRING(80), allowNull: false, unique: true },
      method: { type: DataTypes.STRING(30), allowNull: false },
      billingFirstName: { type: DataTypes.STRING(120) },
      billingStreet: { type: DataTypes.STRING(255) },
      billingApt: { type: DataTypes.STRING(120) },
      billingCity: { type: DataTypes.STRING(120) },
      billingPhone: { type: DataTypes.STRING(80) },
      billingEmail: { type: DataTypes.STRING(180) },
      billingDate: { type: DataTypes.DATE, allowNull: false },
      dueDate: { type: DataTypes.DATE, allowNull: true },
      itemsJson: { type: DataTypes.TEXT("long"), allowNull: false },
      status: { type: DataTypes.ENUM("pending", "paid", "failed"), allowNull: false, defaultValue: "pending" },
      subtotal: { type: DataTypes.INTEGER.UNSIGNED, allowNull: false, defaultValue: 0 },
      shipping: { type: DataTypes.INTEGER.UNSIGNED, allowNull: false, defaultValue: 0 },
      total: { type: DataTypes.INTEGER.UNSIGNED, allowNull: false, defaultValue: 0 },
    },
    { tableName: "transactions", timestamps: true }
  );
  return Transaction;
};
