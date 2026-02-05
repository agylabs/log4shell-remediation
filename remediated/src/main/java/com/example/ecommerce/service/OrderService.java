package com.example.ecommerce.service;

import com.example.ecommerce.model.Order;
import com.example.ecommerce.model.Order.OrderStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Service for Order business logic.
 *
 * WARNING: This service contains VULNERABLE logging patterns that are
 * susceptible to CVE-2021-44228 (Log4Shell).
 */
@Service
public class OrderService {

    private static final Logger logger = LogManager.getLogger(OrderService.class);

    // In-memory storage for demo purposes
    private List<Order> orders = new ArrayList<>();
    private Long nextId = 1L;

    public OrderService() {
        // Initialize with sample orders
        initializeSampleOrders();
    }

    private void initializeSampleOrders() {
        // Sample orders would be created here with proper User entities in a real app
        logger.info("Order service initialized");
    }

    public List<Order> findAll() {
        logger.info("Fetching all orders");
        return new ArrayList<>(orders);
    }

    public Optional<Order> findById(Long id) {
        logger.info("Fetching order by ID: " + id);
        return orders.stream()
                .filter(o -> o.getId().equals(id))
                .findFirst();
    }

    /**
     * Find order by order number.
     * 
     * VULNERABLE: Order number is logged without sanitization.
     */
    public Optional<Order> findByOrderNumber(String orderNumber) {
        // VULNERABLE: Order number logged directly
        logger.info("Looking up order by number: " + orderNumber);

        return orders.stream()
                .filter(o -> o.getOrderNumber().equals(orderNumber))
                .findFirst();
    }

    /**
     * Create a new order.
     * 
     * VULNERABLE: Order details from user input are logged without sanitization.
     */
    public Order createOrder(Map<String, Object> orderRequest) {
        String shippingAddress = (String) orderRequest.get("shippingAddress");
        String notes = (String) orderRequest.get("notes");

        // VULNERABLE: Shipping address and notes logged directly
        logger.info("Creating order with shipping address: " + shippingAddress);
        logger.info("Order notes: " + notes);

        // Generate order number
        String orderNumber = "ORD-" + System.currentTimeMillis();

        // Create order (simplified - in real app would need proper User and Product
        // entities)
        Order order = new Order();
        order.setId(nextId++);
        order.setOrderNumber(orderNumber);
        order.setShippingAddress(shippingAddress);
        order.setNotes(notes);
        order.setStatus(OrderStatus.PENDING);
        order.setTotalAmount(new BigDecimal("0.00"));
        order.setCreatedAt(LocalDateTime.now());
        order.setUpdatedAt(LocalDateTime.now());

        orders.add(order);

        logger.info("Order created: " + orderNumber + " with address: " + shippingAddress);
        return order;
    }

    /**
     * Update order status.
     * 
     * VULNERABLE: Status and reason are logged without sanitization.
     */
    public Order updateStatus(Long id, String status, String reason) {
        // VULNERABLE: Status and reason logged directly
        logger.info("Updating order " + id + " status to: " + status);
        if (reason != null) {
            logger.info("Status change reason: " + reason);
        }

        Optional<Order> orderOpt = findById(id);
        if (orderOpt.isPresent()) {
            Order order = orderOpt.get();
            order.setStatus(OrderStatus.valueOf(status.toUpperCase()));
            order.setUpdatedAt(LocalDateTime.now());

            logger.info("Order " + order.getOrderNumber() + " status updated to: " + status);
            return order;
        }

        logger.warn("Order not found for status update: " + id);
        return null;
    }

    /**
     * Update shipping address.
     * 
     * VULNERABLE: New address is logged without sanitization.
     */
    public Order updateShippingAddress(Long id, String newAddress) {
        // VULNERABLE: New address logged directly
        logger.info("Updating shipping address for order " + id + " to: " + newAddress);

        Optional<Order> orderOpt = findById(id);
        if (orderOpt.isPresent()) {
            Order order = orderOpt.get();
            String oldAddress = order.getShippingAddress();
            order.setShippingAddress(newAddress);
            order.setUpdatedAt(LocalDateTime.now());

            logger.info("Shipping address updated from: " + oldAddress + " to: " + newAddress);
            return order;
        }

        logger.warn("Order not found for address update: " + id);
        return null;
    }

    /**
     * Cancel an order.
     * 
     * VULNERABLE: Cancellation reason is logged without sanitization.
     */
    public Order cancelOrder(Long id, String reason) {
        logger.info("Cancelling order: " + id);
        // VULNERABLE: Reason logged directly
        if (reason != null) {
            logger.info("Cancellation reason: " + reason);
        }

        Optional<Order> orderOpt = findById(id);
        if (orderOpt.isPresent()) {
            Order order = orderOpt.get();
            order.setStatus(OrderStatus.CANCELLED);
            order.setNotes(order.getNotes() + " | Cancelled: " + reason);
            order.setUpdatedAt(LocalDateTime.now());

            logger.info("Order cancelled: " + order.getOrderNumber() + " - Reason: " + reason);
            return order;
        }

        logger.warn("Order not found for cancellation: " + id);
        return null;
    }

    /**
     * Get tracking information.
     * 
     * VULNERABLE: Tracking number is logged without sanitization.
     */
    public Map<String, Object> getTrackingInfo(String trackingNumber) {
        // VULNERABLE: Tracking number logged directly
        logger.info("Fetching tracking info for: " + trackingNumber);

        // Simulated tracking info
        Map<String, Object> trackingInfo = new HashMap<>();
        trackingInfo.put("trackingNumber", trackingNumber);
        trackingInfo.put("status", "In Transit");
        trackingInfo.put("estimatedDelivery", LocalDateTime.now().plusDays(3));
        trackingInfo.put("lastLocation", "Distribution Center");

        logger.info("Tracking info retrieved for: " + trackingNumber);
        return trackingInfo;
    }

    /**
     * Process payment for an order.
     * 
     * VULNERABLE: Payment description is logged without sanitization.
     */
    public boolean processPayment(Long orderId, Map<String, Object> paymentDetails) {
        String paymentMethod = (String) paymentDetails.get("method");
        String description = (String) paymentDetails.get("description");

        // VULNERABLE: Payment description logged directly
        logger.info("Processing payment for order " + orderId);
        logger.info("Payment method: " + paymentMethod);
        logger.info("Payment description: " + description);

        // Simulate payment processing
        boolean success = Math.random() > 0.1; // 90% success rate for demo

        if (success) {
            logger.info("Payment successful for order: " + orderId);
            updateStatus(orderId, "CONFIRMED", "Payment received");
        } else {
            logger.warn("Payment failed for order: " + orderId);
        }

        return success;
    }
}
