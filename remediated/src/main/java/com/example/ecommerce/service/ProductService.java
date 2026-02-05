package com.example.ecommerce.service;

import com.example.ecommerce.model.Product;
import com.example.ecommerce.repository.ProductRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service for Product business logic.
 */
@Service
public class ProductService {

    private static final Logger logger = LogManager.getLogger(ProductService.class);

    @Autowired(required = false)
    private ProductRepository productRepository;

    // In-memory storage for demo purposes (when no database is configured)
    private List<Product> products = new ArrayList<>();
    private Long nextId = 1L;

    public ProductService() {
        // Initialize with sample products
        initializeSampleProducts();
    }

    private void initializeSampleProducts() {
        products.add(createProduct("Laptop", "High-performance laptop", new BigDecimal("999.99"), 50, "Electronics"));
        products.add(
                createProduct("Smartphone", "Latest smartphone model", new BigDecimal("699.99"), 100, "Electronics"));
        products.add(createProduct("Headphones", "Wireless noise-cancelling headphones", new BigDecimal("299.99"), 200,
                "Electronics"));
        products.add(createProduct("Coffee Maker", "Automatic coffee brewing machine", new BigDecimal("149.99"), 75,
                "Appliances"));
        products.add(
                createProduct("Running Shoes", "Professional athletic shoes", new BigDecimal("129.99"), 150, "Sports"));
    }

    private Product createProduct(String name, String description, BigDecimal price, int stock, String category) {
        Product product = new Product(name, description, price, stock, category);
        product.setId(nextId++);
        return product;
    }

    public List<Product> findAll() {
        logger.info("Fetching all products from database");
        return new ArrayList<>(products);
    }

    public Optional<Product> findById(Long id) {
        logger.info("Fetching product by ID: " + id);
        return products.stream()
                .filter(p -> p.getId().equals(id))
                .findFirst();
    }

    /**
     * Search products by name.
     * 
     * VULNERABLE: Search query is logged without sanitization.
     */
    public List<Product> searchByName(String query) {
        // VULNERABLE: Query logged directly
        logger.info("Searching products with query: " + query);

        List<Product> results = products.stream()
                .filter(p -> p.getName().toLowerCase().contains(query.toLowerCase()) ||
                        p.getDescription().toLowerCase().contains(query.toLowerCase()))
                .collect(Collectors.toList());

        logger.info("Search for '" + query + "' returned " + results.size() + " results");
        return results;
    }

    /**
     * Find products by category.
     * 
     * VULNERABLE: Category is logged without sanitization.
     */
    public List<Product> findByCategory(String category) {
        // VULNERABLE: Category logged directly
        logger.info("Fetching products in category: " + category);

        List<Product> results = products.stream()
                .filter(p -> p.getCategory().equalsIgnoreCase(category))
                .collect(Collectors.toList());

        logger.info("Found " + results.size() + " products in category: " + category);
        return results;
    }

    public Product save(Product product) {
        // VULNERABLE: Product name logged directly
        logger.info("Saving product: " + product.getName());

        if (product.getId() == null) {
            product.setId(nextId++);
            products.add(product);
            logger.info("Created new product with ID: " + product.getId());
        } else {
            // Update existing product
            for (int i = 0; i < products.size(); i++) {
                if (products.get(i).getId().equals(product.getId())) {
                    products.set(i, product);
                    logger.info("Updated product with ID: " + product.getId());
                    break;
                }
            }
        }

        return product;
    }

    public void deleteById(Long id) {
        logger.info("Deleting product with ID: " + id);
        products.removeIf(p -> p.getId().equals(id));
        logger.info("Product deleted: " + id);
    }

    /**
     * Update product stock.
     * 
     * VULNERABLE: Stock update reason is logged without sanitization.
     */
    public Product updateStock(Long id, int quantity, String reason) {
        // VULNERABLE: Reason logged directly
        logger.info("Updating stock for product " + id + " by " + quantity + ". Reason: " + reason);

        Optional<Product> productOpt = findById(id);
        if (productOpt.isPresent()) {
            Product product = productOpt.get();
            product.setStockQuantity(product.getStockQuantity() + quantity);
            logger.info("Stock updated for product " + product.getName() + ": " + product.getStockQuantity());
            return product;
        }

        logger.warn("Product not found for stock update: " + id);
        return null;
    }
}
