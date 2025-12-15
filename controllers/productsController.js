const { Product } = require('../models');

exports.list = async function list(req, res, next) {
  try {
    const rows = await Product.findAll({
      attributes: ['id', 'name', 'slug', 'price', 'category', 'rating', 'isNew', 'image'],
      limit: 50,
      order: [['id', 'ASC']],
    });
    return res.json({ items: rows });
  } catch (err) {
    next(err);
  }
};

exports.detail = async function detail(req, res, next) {
  try {
    const item = await Product.findOne({
      where: { slug: req.params.slug },
      attributes: ['id', 'name', 'slug', 'price', 'category', 'rating', 'isNew', 'image', 'description'],
    });
    if (!item) return res.status(404).json({ message: 'Product not found' });
    return res.json(item);
  } catch (err) {
    next(err);
  }
};

function makeSlug(name) {
  return String(name || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-');
}

exports.create = async function create(req, res, next) {
  try {
    const { name, price, category, image, description, rating, isNew } = req.body || {};
    if (!name || price == null) return res.status(400).json({ message: 'name and price are required' });
    let slug = req.body.slug || makeSlug(name);
    const exists = await Product.findOne({ where: { slug }, attributes: ['id'] });
    if (exists) slug = `${slug}-${Date.now().toString(36)}`;
    const created = await Product.create({
      name,
      slug,
      price: Number(price),
      category: category || null,
      image: image || null,
      description: description || null,
      rating: rating != null ? Number(rating) : null,
      isNew: !!isNew,
    });
    return res.status(201).json({ id: created.id, slug: created.slug });
  } catch (err) {
    next(err);
  }
};

exports.update = async function update(req, res, next) {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: 'invalid id' });
    const item = await Product.findOne({ where: { id } });
    if (!item) return res.status(404).json({ message: 'Product not found' });
    const { name, price, category, image, description, rating, isNew, slug } = req.body || {};
    const payload = {};
    if (name != null) payload.name = name;
    if (price != null) payload.price = Number(price);
    if (category != null) payload.category = category;
    if (image != null) payload.image = image;
    if (description != null) payload.description = description;
    if (rating != null) payload.rating = Number(rating);
    if (isNew != null) payload.isNew = !!isNew;
    if (slug != null) {
      const s = String(slug || '');
      payload.slug = s ? makeSlug(s) : item.slug;
    }
    await Product.update(payload, { where: { id } });
    const updated = await Product.findOne({
      where: { id },
      attributes: ['id', 'name', 'slug', 'price', 'category', 'rating', 'isNew', 'image', 'description'],
    });
    return res.json(updated);
  } catch (err) {
    next(err);
  }
};

exports.remove = async function remove(req, res, next) {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: 'invalid id' });
    const item = await Product.findOne({ where: { id }, attributes: ['id'] });
    if (!item) return res.status(404).json({ message: 'Product not found' });
    await Product.destroy({ where: { id } });
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
};

exports.patch = async function patch(req, res, next) {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: 'invalid id' });
    const item = await Product.findOne({ where: { id } });
    if (!item) return res.status(404).json({ message: 'Product not found' });
    const { name, price, category, image, description, rating, isNew, slug } = req.body || {};
    const payload = {};
    if (name != null) payload.name = name;
    if (price != null) payload.price = Number(price);
    if (category != null) payload.category = category;
    if (image != null) payload.image = image;
    if (description != null) payload.description = description;
    if (rating != null) payload.rating = Number(rating);
    if (isNew != null) payload.isNew = !!isNew;
    if (slug != null) {
      const s = String(slug || '');
      payload.slug = s ? makeSlug(s) : item.slug;
    }
    await Product.update(payload, { where: { id } });
    const updated = await Product.findOne({
      where: { id },
      attributes: ['id', 'name', 'slug', 'price', 'category', 'rating', 'isNew', 'image', 'description'],
    });
    return res.json(updated);
  } catch (err) {
    next(err);
  }
};
