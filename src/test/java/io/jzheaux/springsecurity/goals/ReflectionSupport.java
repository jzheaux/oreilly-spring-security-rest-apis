package io.jzheaux.springsecurity.goals;

import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.stream.Stream;

public class ReflectionSupport {
	private ReflectionSupport() {}

	static Field getDeclaredFieldByType(Class<?> type, Class<?> fieldType) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> f.getType() == fieldType)
				.findFirst().orElse(null);
	}

	static Field getDeclaredFieldByName(Class<?> type, String name) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> f.getName().equals(name))
				.findFirst().orElse(null);
	}

	static Field getDeclaredFieldByColumnName(Class<?> type, String columnName) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> {
					String name = null;
					Column column = f.getAnnotation(Column.class);
					Id id = f.getAnnotation(Id.class);
					JoinColumn joinColumn = f.getAnnotation(JoinColumn.class);

					if (column != null) {
						name = column.name();
					} else if (joinColumn != null) {
						name = joinColumn.name();
					} else if (id != null) {
						name = "";
					}

					if ("".equals(name)) {
						name = f.getName();
					}

					return columnName.equals(name);
				})
				.findFirst().orElse(null);
	}

	static Field getDeclaredFieldHavingAnnotation(Class<?> type, Class<? extends Annotation> annotation) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> f.getAnnotation(annotation) != null)
				.findFirst().orElse(null);
	}

	static Constructor<?> getConstructor(Class<?> type, Class<?>... parameterTypes) {
		try {
			return type.getDeclaredConstructor(parameterTypes);
		} catch (Exception ignored) {
			return null;
		}
	}

	static <T> T getProperty(Object o, Field field) {
		try {
			field.setAccessible(true);
			return (T) field.get(o);
		} catch (Exception e) {
			throw new RuntimeException("Tried to get " + field + " from " + o, e);
		}
	}

	static <T extends Annotation> T annotation(Class<T> annotation, String method, Class<?>... params) {
		try {
			Method m = GoalController.class.getDeclaredMethod(method, params);
			return m.getAnnotation(annotation);
		} catch (Exception e) {
			return null;
		}
	}
}
