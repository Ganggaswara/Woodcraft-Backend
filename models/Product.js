const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  const Product = sequelize.define(
    'Product',
    {
      id: { type: DataTypes.INTEGER.UNSIGNED, primaryKey: true, autoIncrement: true },
      name: { type: DataTypes.STRING(150), allowNull: false },
      slug: { type: DataTypes.STRING(180), allowNull: false, unique: true },
      description: { type: DataTypes.TEXT },
      price: { type: DataTypes.INTEGER, allowNull: false },
      image: { type: DataTypes.STRING(255) },
      category: { type: DataTypes.STRING(50) },
      rating: { type: DataTypes.DECIMAL(2, 1) },
      isNew: { type: DataTypes.BOOLEAN, defaultValue: false },
    },
    { tableName: 'products', timestamps: true }
  );
  return Product;
};
