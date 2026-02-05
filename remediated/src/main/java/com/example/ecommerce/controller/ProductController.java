package com.example.ecommerce.controller;

import com.example.ecommerce.model.Product;
import com.example.ecommerce.security.InputSanitizer;
import com.example.ecommerce.service.ProductService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * REST Controller for Product operations (REMEDIATED).
 * 
 * Security improvements:
 * 1. All user input is sanitized before logging using InputSanitizer
 * 2. Parameterized logging is used instead of string concatenation
 * 3. Input validation is performed before processing
 */
@RestController
@RequestMapping("/api/products")
public class ProductController {

    private static final Logger logger = LogManager.getLogger(ProductController.class);

    @Autowired
    private ProductService productService;

    /**
     * Get all products.
     */
    @GetMapping
    public ResponseEntity<List<Product>> getAllProducts() {
        logger.info("Fetching all products");
        List<Product> products = productService.findAll();
        logger.info("Found {} products", products.size());
        return ResponseEntity.ok(products);
    }

    /**
     * Get product by ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<Product> getProductById(@PathVariable Long id) {
        logger.info("Fetching product with ID: {}", id);
        Optional<Product> product = productService.findById(id);
        if (product.isPresent()) {
            logger.info("Found product: {}", InputSanitizer.sanitize(product.get().getName()));
            return ResponseEntity.ok(product.get());
        }
        logger.warn("Product not found with ID: {}", id);
        return ResponseEntity.notFound().build();
    }

    /**
     * Search products by query.
     * 
     * SECURED: User input is sanitized before logging.
     */
    @GetMapping("/search")
    public ResponseEntity<List<Product>> searchProducts(@RequestParam String query) {
        // SECURED: Sanitize user input before logging
        String sanitizedQuery = InputSanitizer.sanitizeWithAudit(query, "search query");
        logger.info("Search query received: {}", sanitizedQuery);

        // Check for suspicious patterns
        if (InputSanitizer.containsSuspiciousPatterns(query)) {
            logger.warn("SECURITY: Suspicious pattern detected in search query");
        }

        List<Product> results = productService.searchByName(query);

        // SECURED: Using parameterized logging
        logger.info("Search completed - Query: {}, Results: {}", sanitizedQuery, results.size());

        return ResponseEntity.ok(results);
    }

    /**
     * Search products by category.
     * 
     * SECURED: Category parameter is sanitized before logging.
     */
    @GetMapping("/category/{category}")
    public ResponseEntity<List<Product>> getProductsByCategory(@PathVariable String category) {
        // SECURED: Sanitize path variable
        String sanitizedCategory = InputSanitizer.sanitize(category);
        logger.info("Fetching products in category: {}", sanitizedCategory);

        List<Product> products = productService.findByCategory(category);

        logger.info("Found {} products in category: {}", products.size(), sanitizedCategory);
        return ResponseEntity.ok(products);
    }

    /**
     * Create a new product.
     * 
     * SECURED: Product details are sanitized before logging.
     */
    @PostMapping
    public ResponseEntity<Product> createProduct(@RequestBody Product product) {
        // SECURED: Sanitize product name and description
        String sanitizedName = InputSanitizer.sanitize(product.getName());
        String sanitizedDescription = InputSanitizer.truncateAndSanitize(product.getDescription(), 100);

        logger.info("Creating new product: {}", sanitizedName);
        logger.debug("Product description: {}", sanitizedDescription);

        Product savedProduct = productService.save(product);

        logger.info("Product created successfully with ID: {}", savedProduct.getId());
        return ResponseEntity.ok(savedProduct);
    }

    /**
     * Update an existing product.
     * 
     * SECURED: Updated product details are sanitized before logging.
     */
    @PutMapping("/{id}")
    public ResponseEntity<Product> updateProduct(@PathVariable Long id, @RequestBody Product product) {
        logger.info("Updating product with ID: {}", id);

        // SECURED: Sanitize product name
        String sanitizedName = InputSanitizer.sanitize(product.getName());
        logger.info("New product name: {}", sanitizedName);

        Optional<Product> existingProduct = productService.findById(id);
        if (existingProduct.isEmpty()) {
            logger.warn("Product not found for update: {}", id);
            return ResponseEntity.notFound().build();
        }

        product.setId(id);
        Product updatedProduct = productService.save(product);

        logger.info("Product updated successfully: {}", InputSanitizer.sanitize(updatedProduct.getName()));
        return ResponseEntity.ok(updatedProduct);
    }

    /**
     * Delete a product.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteProduct(@PathVariable Long id) {
        logger.info("Deleting product with ID: {}", id);

        Optional<Product> product = productService.findById(id);
        if (product.isEmpty()) {
            logger.warn("Product not found for deletion: {}", id);
            return ResponseEntity.notFound().build();
        }

        productService.deleteById(id);
        logger.info("Product deleted successfully: {}", id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Add a review to a product.
     * 
     * SECURED: User-submitted review text is sanitized before logging.
     */
    @PostMapping("/{id}/reviews")
    public ResponseEntity<String> addReview(
            @PathVariable Long id,
            @RequestParam String reviewer,
            @RequestParam String reviewText) {

        // SECURED: Sanitize all user input
        String sanitizedReviewer = InputSanitizer.sanitize(reviewer);
        String sanitizedReviewText = InputSanitizer.truncateAndSanitize(reviewText, 200);

        logger.info("New review from: {}", sanitizedReviewer);
        logger.info("Review text: {}", sanitizedReviewText);

        // In a real application, this would save the review
        logger.info("Review added to product {} by {}", id, sanitizedReviewer);

        return ResponseEntity.ok("Review added successfully");
    }
}
