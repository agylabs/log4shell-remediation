package com.example.ecommerce.controller;

import com.example.ecommerce.model.Order;
import com.example.ecommerce.security.InputSanitizer;
import com.example.ecommerce.service.OrderService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * REST Controller for Order operations (REMEDIATED).
 * 
 * Security improvements:
 * 1. All user input is sanitized before logging using InputSanitizer
 * 2. Parameterized logging is used instead of string concatenation
 * 3. Suspicious input patterns trigger security alerts
 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private static final Logger logger = LogManager.getLogger(OrderController.class);

    @Autowired
    private OrderService orderService;

    /**
     * Get all orders for the current user.
     */
    @GetMapping
    public ResponseEntity<List<Order>> getAllOrders() {
        logger.info("Fetching all orders");
        List<Order> orders = orderService.findAll();
        logger.info("Found {} orders", orders.size());
        return ResponseEntity.ok(orders);
    }

    /**
     * Get order by ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<Order> getOrderById(@PathVariable Long id) {
        logger.info("Fetching order with ID: {}", id);
        Optional<Order> order = orderService.findById(id);
        if (order.isPresent()) {
            logger.info("Found order: {}", InputSanitizer.sanitize(order.get().getOrderNumber()));
            return ResponseEntity.ok(order.get());
        }
        logger.warn("Order not found with ID: {}", id);
        return ResponseEntity.notFound().build();
    }

    /**
     * Get order by order number.
     * 
     * SECURED: Order number is sanitized before logging.
     */
    @GetMapping("/number/{orderNumber}")
    public ResponseEntity<Order> getOrderByNumber(@PathVariable String orderNumber) {
        // SECURED: Sanitize order number
        String sanitizedOrderNumber = InputSanitizer.sanitizeWithAudit(orderNumber, "order number");
        logger.info("Looking up order by number: {}", sanitizedOrderNumber);

        Optional<Order> order = orderService.findByOrderNumber(orderNumber);
        if (order.isPresent()) {
            logger.info("Found order: {} with status: {}",
                    sanitizedOrderNumber,
                    order.get().getStatus());
            return ResponseEntity.ok(order.get());
        }

        logger.warn("Order not found with number: {}", sanitizedOrderNumber);
        return ResponseEntity.notFound().build();
    }

    /**
     * Create a new order.
     * 
     * SECURED: Shipping address and notes are sanitized before logging.
     */
    @PostMapping
    public ResponseEntity<Order> createOrder(@RequestBody Map<String, Object> orderRequest) {
        // SECURED: Sanitize all user-provided strings
        String shippingAddress = (String) orderRequest.get("shippingAddress");
        String notes = (String) orderRequest.get("notes");

        String sanitizedAddress = InputSanitizer.truncateAndSanitize(shippingAddress, 200);
        String sanitizedNotes = InputSanitizer.truncateAndSanitize(notes, 500);

        logger.info("Creating new order with shipping address: {}", sanitizedAddress);
        logger.info("Order notes: {}", sanitizedNotes);

        Order order = orderService.createOrder(orderRequest);

        logger.info("Order created successfully: {}", InputSanitizer.sanitize(order.getOrderNumber()));

        return ResponseEntity.ok(order);
    }

    /**
     * Update order status.
     * 
     * SECURED: Status and reason are sanitized before logging.
     */
    @PutMapping("/{id}/status")
    public ResponseEntity<Order> updateOrderStatus(
            @PathVariable Long id,
            @RequestParam String status,
            @RequestParam(required = false) String reason) {

        // SECURED: Sanitize status and reason
        String sanitizedStatus = InputSanitizer.sanitize(status);
        logger.info("Updating order {} status to: {}", id, sanitizedStatus);

        if (reason != null) {
            String sanitizedReason = InputSanitizer.truncateAndSanitize(reason, 200);
            logger.info("Status change reason: {}", sanitizedReason);
        }

        Optional<Order> order = orderService.findById(id);
        if (order.isEmpty()) {
            logger.warn("Order not found for status update: {}", id);
            return ResponseEntity.notFound().build();
        }

        Order updatedOrder = orderService.updateStatus(id, status, reason);
        logger.info("Order status updated: {} -> {}",
                InputSanitizer.sanitize(updatedOrder.getOrderNumber()),
                sanitizedStatus);

        return ResponseEntity.ok(updatedOrder);
    }

    /**
     * Update shipping address.
     * 
     * SECURED: New address is sanitized before logging.
     */
    @PutMapping("/{id}/shipping")
    public ResponseEntity<Order> updateShippingAddress(
            @PathVariable Long id,
            @RequestBody Map<String, String> addressRequest) {

        String newAddress = addressRequest.get("address");

        // SECURED: Sanitize new address
        String sanitizedAddress = InputSanitizer.truncateAndSanitize(newAddress, 200);
        logger.info("Updating shipping address for order {} to: {}", id, sanitizedAddress);

        Order updatedOrder = orderService.updateShippingAddress(id, newAddress);

        logger.info("Shipping address updated for order: {}",
                InputSanitizer.sanitize(updatedOrder.getOrderNumber()));
        return ResponseEntity.ok(updatedOrder);
    }

    /**
     * Cancel an order.
     * 
     * SECURED: Cancellation reason is sanitized before logging.
     */
    @PostMapping("/{id}/cancel")
    public ResponseEntity<Order> cancelOrder(
            @PathVariable Long id,
            @RequestParam(required = false) String reason) {

        logger.info("Cancelling order: {}", id);

        // SECURED: Sanitize cancellation reason
        if (reason != null) {
            String sanitizedReason = InputSanitizer.truncateAndSanitize(reason, 200);
            logger.info("Cancellation reason: {}", sanitizedReason);
        }

        Order cancelledOrder = orderService.cancelOrder(id, reason);

        logger.info("Order cancelled successfully: {}",
                InputSanitizer.sanitize(cancelledOrder.getOrderNumber()));
        return ResponseEntity.ok(cancelledOrder);
    }

    /**
     * Track order by tracking number.
     * 
     * SECURED: Tracking number is sanitized before logging.
     */
    @GetMapping("/track/{trackingNumber}")
    public ResponseEntity<Map<String, Object>> trackOrder(@PathVariable String trackingNumber) {
        // SECURED: Sanitize tracking number
        String sanitizedTracking = InputSanitizer.sanitizeWithAudit(trackingNumber, "tracking number");
        logger.info("Tracking order with number: {}", sanitizedTracking);

        Map<String, Object> trackingInfo = orderService.getTrackingInfo(trackingNumber);

        if (trackingInfo == null) {
            logger.warn("Tracking information not found for: {}", sanitizedTracking);
            return ResponseEntity.notFound().build();
        }

        logger.info("Tracking info retrieved for: {}", sanitizedTracking);
        return ResponseEntity.ok(trackingInfo);
    }

    /**
     * Add a comment to an order.
     * 
     * SECURED: Comment text is sanitized before logging.
     */
    @PostMapping("/{id}/comments")
    public ResponseEntity<String> addComment(
            @PathVariable Long id,
            @RequestParam String comment) {

        // SECURED: Sanitize comment
        String sanitizedComment = InputSanitizer.truncateAndSanitize(comment, 500);
        logger.info("Adding comment to order {}: {}", id, sanitizedComment);

        // In a real application, this would save the comment
        logger.info("Comment added successfully to order: {}", id);

        return ResponseEntity.ok("Comment added successfully");
    }
}
