package com.example.ecommerce.controller;

import com.example.ecommerce.model.Order;
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
 * REST Controller for Order operations.
 * 
 * WARNING: This controller contains VULNERABLE logging patterns that are
 * susceptible to CVE-2021-44228 (Log4Shell). Order details and user input
 * are logged directly without sanitization.
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
        logger.info("Found " + orders.size() + " orders");
        return ResponseEntity.ok(orders);
    }

    /**
     * Get order by ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<Order> getOrderById(@PathVariable Long id) {
        logger.info("Fetching order with ID: " + id);
        Optional<Order> order = orderService.findById(id);
        if (order.isPresent()) {
            logger.info("Found order: " + order.get().getOrderNumber());
            return ResponseEntity.ok(order.get());
        }
        logger.warn("Order not found with ID: " + id);
        return ResponseEntity.notFound().build();
    }

    /**
     * Get order by order number.
     * 
     * VULNERABLE: Order number from user input is logged without sanitization.
     */
    @GetMapping("/number/{orderNumber}")
    public ResponseEntity<Order> getOrderByNumber(@PathVariable String orderNumber) {
        // VULNERABLE: Order number logged directly
        logger.info("Looking up order by number: " + orderNumber);

        Optional<Order> order = orderService.findByOrderNumber(orderNumber);
        if (order.isPresent()) {
            logger.info("Found order: " + order.get().getOrderNumber() + " with status: " + order.get().getStatus());
            return ResponseEntity.ok(order.get());
        }

        logger.warn("Order not found with number: " + orderNumber);
        return ResponseEntity.notFound().build();
    }

    /**
     * Create a new order.
     * 
     * VULNERABLE: Shipping address and notes from request are logged without
     * sanitization.
     */
    @PostMapping
    public ResponseEntity<Order> createOrder(@RequestBody Map<String, Object> orderRequest) {
        // VULNERABLE: Shipping address from user input
        String shippingAddress = (String) orderRequest.get("shippingAddress");
        String notes = (String) orderRequest.get("notes");

        logger.info("Creating new order with shipping address: " + shippingAddress);
        logger.info("Order notes: " + notes);

        // Create order (simplified for demo)
        Order order = orderService.createOrder(orderRequest);

        logger.info("Order created successfully: " + order.getOrderNumber());
        logger.debug("Full order details: " + order);

        return ResponseEntity.ok(order);
    }

    /**
     * Update order status.
     * 
     * VULNERABLE: Status value and reason logged without sanitization.
     */
    @PutMapping("/{id}/status")
    public ResponseEntity<Order> updateOrderStatus(
            @PathVariable Long id,
            @RequestParam String status,
            @RequestParam(required = false) String reason) {

        // VULNERABLE: Status and reason from user input
        logger.info("Updating order " + id + " status to: " + status);
        if (reason != null) {
            logger.info("Status change reason: " + reason);
        }

        Optional<Order> order = orderService.findById(id);
        if (order.isEmpty()) {
            logger.warn("Order not found for status update: " + id);
            return ResponseEntity.notFound().build();
        }

        Order updatedOrder = orderService.updateStatus(id, status, reason);
        logger.info("Order status updated: " + updatedOrder.getOrderNumber() + " -> " + status);

        return ResponseEntity.ok(updatedOrder);
    }

    /**
     * Update shipping address.
     * 
     * VULNERABLE: New shipping address logged without sanitization.
     */
    @PutMapping("/{id}/shipping")
    public ResponseEntity<Order> updateShippingAddress(
            @PathVariable Long id,
            @RequestBody Map<String, String> addressRequest) {

        String newAddress = addressRequest.get("address");

        // VULNERABLE: Address from user input
        logger.info("Updating shipping address for order " + id + " to: " + newAddress);

        Order updatedOrder = orderService.updateShippingAddress(id, newAddress);

        logger.info("Shipping address updated for order: " + updatedOrder.getOrderNumber());
        return ResponseEntity.ok(updatedOrder);
    }

    /**
     * Cancel an order.
     * 
     * VULNERABLE: Cancellation reason logged without sanitization.
     */
    @PostMapping("/{id}/cancel")
    public ResponseEntity<Order> cancelOrder(
            @PathVariable Long id,
            @RequestParam(required = false) String reason) {

        logger.info("Cancelling order: " + id);
        // VULNERABLE: Cancellation reason from user input
        if (reason != null) {
            logger.info("Cancellation reason: " + reason);
        }

        Order cancelledOrder = orderService.cancelOrder(id, reason);

        logger.info("Order cancelled successfully: " + cancelledOrder.getOrderNumber());
        return ResponseEntity.ok(cancelledOrder);
    }

    /**
     * Track order by tracking number.
     * 
     * VULNERABLE: Tracking number logged without sanitization.
     */
    @GetMapping("/track/{trackingNumber}")
    public ResponseEntity<Map<String, Object>> trackOrder(@PathVariable String trackingNumber) {
        // VULNERABLE: Tracking number from user input
        logger.info("Tracking order with number: " + trackingNumber);

        Map<String, Object> trackingInfo = orderService.getTrackingInfo(trackingNumber);

        if (trackingInfo == null) {
            logger.warn("Tracking information not found for: " + trackingNumber);
            return ResponseEntity.notFound().build();
        }

        logger.info("Tracking info retrieved for: " + trackingNumber);
        return ResponseEntity.ok(trackingInfo);
    }

    /**
     * Add a comment to an order.
     * 
     * VULNERABLE: Comment text logged without sanitization.
     */
    @PostMapping("/{id}/comments")
    public ResponseEntity<String> addComment(
            @PathVariable Long id,
            @RequestParam String comment) {

        // VULNERABLE: Comment from user input
        logger.info("Adding comment to order " + id + ": " + comment);

        // In a real application, this would save the comment
        logger.info("Comment added successfully to order: " + id);

        return ResponseEntity.ok("Comment added successfully");
    }
}
