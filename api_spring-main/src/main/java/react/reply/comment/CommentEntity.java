package react.reply.comment;

import java.sql.Timestamp;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.CurrentTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import react.reply.user.UserEntity;

@Getter
@Setter
@Entity
@Table(name="comment")
@ToString
public class CommentEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int no;
	@Column(name="parent_no")
	private int parentno;
	private String content;
	@CreationTimestamp
	private Timestamp writedate;
	
	@ManyToOne
	@JoinColumn(name="user_no")
	private UserEntity user; 
}
