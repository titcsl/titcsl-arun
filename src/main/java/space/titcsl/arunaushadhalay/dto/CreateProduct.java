package space.titcsl.arunaushadhalay.dto;

import jakarta.persistence.Column;
import jakarta.persistence.Lob;
import lombok.Data;

import java.sql.Blob;

@Data
public class CreateProduct {
    private String product_name;
    private String product_desc;
    private String actual_price;
    private String discounted_price;
    private String product_stock;

}
