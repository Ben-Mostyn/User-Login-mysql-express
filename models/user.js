const connection = require("../connection");
const { DataTypes } = require("sequelize");

const User = connection.define(
  "User",
  {
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
  },
  { indexes: [{ unique: true, fields: ["name"] }] }
);

module.exports = User;
