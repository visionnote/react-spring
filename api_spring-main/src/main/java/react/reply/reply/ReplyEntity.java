package react.reply.reply;

import java.sql.Timestamp;
import java.util.List;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.CurrentTimestamp;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import react.reply.comment.CommentEntity;
import react.reply.user.UserEntity;

@Getter
@Setter
@Entity
@Table(name = "reply")
@ToString
public class ReplyEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int no;
	private String title;
	private String content;
	@CreationTimestamp
	private Timestamp writedate;
	private int viewcnt;
	private String filename_org;
	private String filename_real;
	private int likecnt;
	//private int user_no;
	private int gno;
	private int ono;
	private int nested;
	
	@OneToMany(mappedBy = "parentno")
	private List<CommentEntity> comment;
	
	@ManyToOne
	@JoinColumn(name="user_no")
	private UserEntity user; 
	
}
