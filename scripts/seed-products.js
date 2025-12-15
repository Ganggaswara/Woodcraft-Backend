require("dotenv").config();
const { sequelize, Product, syncModels } = require("../models");

async function run() {
  await sequelize.sync({ force: true });
  await Product.destroy({ where: {}, truncate: true });
  const items = [
    // Bedroom
    {
      id: 1,
      name: "Melah Wardrobe",
      slug: "melah-wardrobe",
      description: "A minimalist solid-wood wardrobe with clean lines and a smooth finish. Ventilated compartments and durable joinery provide ample space for hanging and folding clothes in modern bedrooms.",
      price: 5890000,
      image: "/Bedroom/Melah-wardrobe.jpg",
      category: "bedroom",
      rating: 4.6,
      isNew: true,
    },
    {
      id: 2,
      name: "Putu Nightstand Table",
      slug: "putu-nightstand-table",
      description: "A compact bedside nightstand featuring a soft-close drawer and open shelf. Built from solid wood for everyday use and finished to blend seamlessly with neutral interiors.",
      price: 1190000,
      image: "/Bedroom/Putu-Nightstand-Table.jpg",
      category: "bedroom",
      rating: 4.4,
      isNew: false,
    },
    {
      id: 3,
      name: "Srikandi Bedframe",
      slug: "srikandi-bedframe",
      description: "A solid wood bedframe with refined edges and reinforced slats for stable support. The warm natural tone and smooth finish create a calming centerpiece for your bedroom.",
      price: 3990000,
      image: "/Bedroom/Srikandi-bedframe.jpg",
      category: "bedroom",
      rating: 4.7,
      isNew: true,
    },
    // Dining Room
    {
      id: 4,
      name: "Braya Bar Stoolchair",
      slug: "braya-bar-stoolchair",
      description: "A high bar stool with an ergonomic seat and integrated footrest. Crafted for kitchen islands and bars, it balances lightweight form with sturdy construction for comfortable posture.",
      price: 1590000,
      image: "/Dining-room/Braya-Bar-Stoolchair.jpg",
      category: "dining-room",
      rating: 4.3,
      isNew: false,
    },
    {
      id: 5,
      name: "Nyame Dining Table",
      slug: "nyame-dining-table",
      description: "A family dining table made from premium hardwood with a protective finish and rounded corners. Comfortably seats four to six, ideal for everyday meals and gatherings.",
      price: 5290000,
      image: "/Dining-room/Nyame-Dining-Table.jpg",
      category: "dining-room",
      rating: 4.6,
      isNew: false,
    },
    // Lounge
    {
      id: 6,
      name: "Lounge Chair",
      slug: "lounge-chair",
      description: "A comfort-forward lounge chair with supportive backrest and gentle curves. Optional cushions and a wooden base complement living spaces with a cozy, relaxed feel.",
      price: 2290000,
      image: "/Lounge/Lounge-Chair.jpg",
      category: "lounge",
      rating: 4.5,
      isNew: true,
    },
    {
      id: 7,
      name: "Nara Coffee Table",
      slug: "nara-coffee-table",
      description: "A slim-profile coffee table with practical proportions for smaller living rooms. The solid top and stable legs make it easy to move, use, and maintain.",
      price: 1490000,
      image: "/Lounge/Nara-Coffee-table.jpg",
      category: "lounge",
      rating: 4.2,
      isNew: false,
    },
    {
      id: 8,
      name: "OakWood TV Console",
      slug: "oakwood-tv-console",
      description: "An oak wood TV console with ventilated compartments for media devices and neat cable management. Adjustable shelves and natural grain elevate your media setup.",
      price: 3190000,
      image: "/Lounge/OakWood-TV-Console.jpg",
      category: "lounge",
      rating: 4.4,
      isNew: false,
    },
    {
      id: 9,
      name: "Wayan Coffee Table",
      slug: "wayan-coffee-table",
      description: "A solid wood coffee table with balanced proportions, smooth surface, and durable finish. Ideal for serving, decor, and daily use in the living room.",
      price: 1690000,
      image: "/Lounge/Wayan-Coffee-table.jpg",
      category: "lounge",
      rating: 4.3,
      isNew: false,
    },
    {
      id: 10,
      name: "Zen Floating Shelf",
      slug: "zen-floating-shelf",
      description: "A minimal floating wall shelf with hidden brackets and reinforced load-bearing. Perfect for books, frames, and decor while keeping a clean, modern wall aesthetic.",
      price: 990000,
      image: "/Lounge/Zen-Floating-Shelf.jpg",
      category: "lounge",
      rating: 4.1,
      isNew: false,
    },
    // Office
    {
      id: 11,
      name: "Becik Office Table",
      slug: "becik-office-table",
      description: "A spacious work desk with a broad surface, sturdy frame, and discreet cable pass-through. Designed for productive sessions and fits laptops, monitors, and everyday documents.",
      price: 2790000,
      image: "/Office/Becik-Office-Table.jpg",
      category: "office",
      rating: 4.5,
      isNew: true,
    },
  ];
  await Product.bulkCreate(items);
  await sequelize.close();
}

run().catch(async (e) => {
  console.error(e);
  try {
    await sequelize.close();
  } catch (_) {}
  process.exit(1);
});
