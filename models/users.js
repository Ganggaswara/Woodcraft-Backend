const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  const User = sequelize.define(
    'User',
    {
      id: { type: DataTypes.INTEGER.UNSIGNED, primaryKey: true, autoIncrement: true },
      name: { type: DataTypes.STRING(180), allowNull: false },
      email: { type: DataTypes.STRING(255), allowNull: false, unique: true },
      password: { type: DataTypes.STRING(255), allowNull: false },
      role: { type: DataTypes.STRING(30), defaultValue: 'customer' },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { tableName: 'users', timestamps: false }
  );
  return User;
};
