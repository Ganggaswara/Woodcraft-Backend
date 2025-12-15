const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(
  process.env.MYSQL_DB,
  process.env.MYSQL_USER,
  process.env.MYSQL_PASSWORD,
  {
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    dialect: 'mysql',
    logging: false,
  }
);

const Product = require('./product')(sequelize);
const User = require('./users')(sequelize);
const Transaction = require('./transactions')(sequelize);

async function syncModels() {
  await sequelize.sync({ alter: true });
}

module.exports = { sequelize, Product, User, Transaction, syncModels };
